package main

import "C"

// #cgo LDFLAGS: -lz -lelf

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

type EventType uint32

const (
	EventKprobeSync EventType = iota + 1
	EventKprobeSyncMap
	EventTpSync
)

func NewEventType(eventNum uint32) EventType {
	m := map[uint32]EventType{
		1: EventKprobeSync,
		2: EventKprobeSyncMap,
		3: EventTpSync,
	}

	return m[eventNum]
}

func (e EventType) String() string {
	m := map[EventType]string{
		EventKprobeSync:    "Kprobe Sync Event",
		EventKprobeSyncMap: "Kprobe Sync Event From Hashmap",
		EventTpSync:        "Tracepoint Sync Event",
	}

	return m[e]
}

//
// data structure sent from kernel to userland
//

// data the way eBPF programs see
type data struct {
	StartTime uint64   // 08 bytes: 000-063 : task start time
	Pid       uint32   // 04 bytes: 064-095 : host process id
	Tgid      uint32   // 04 bytes: 096-127: host thread group id
	Ppid      uint32   // 04 bytes: 128-159: host parent process id
	Uid       uint32   // 04 bytes: 160-191: user id
	Gid       uint32   // 04 bytes: 192-223: group id
	Comm      [16]byte // 16 bytes: 224-351: command (task_comm_len)
	Padding   uint32   // 04 bytes: 352-383: padding/empty
	Origin    uint32   // 04 bytes: 384-387: eBPF program that generated event
}

// data the way userland golang program sees
type goData struct {
	Origin    EventType
	StartTime uint
	Pid       uint
	Tgid      uint
	Ppid      uint
	Uid       uint
	Gid       uint
	Comm      string
}

func main() {
	// create an eBPF module using eBPF object file from filesystem
	// bpfModule, err = bpf.NewModuleFromFile("drafts.bpf.core.o")
	// OR, much better, unpack the embedded eBPF object file into memory
	b, err := EmbeddedBPF.ReadFile("build/drafts.bpf.core.o")
	if err != nil {
		Error(err)
	}

	// create an eBPF module (using eBPF object file from memory)
	bpfModule, err := bpf.NewModuleFromBuffer(b, "drafts.bpf.core.o")
	if err != nil {
		Error(err)
	}
	defer bpfModule.Close()

	// get the eBPF map object from the unloaded eBPF object
	bpfMapEvents, err := bpfModule.GetMap("perfbuffer")
	if err != nil {
		Error(err)
	}

	// ... and resize it (default: 1024) before loading eBPF object into kernel
	err = bpfMapEvents.Resize(10240) // 10k events possible in perf buffer map
	if err != nil {
		Error(err)
	}

	// load the eBPF object into kernel
	if err = bpfModule.BPFLoadObject(); err != nil {
		Error(err)
	}

	//
	// EXAMPLES: eBPF program types
	//

	// KPROBE:
	// SYSCALL_DEFINE0(sync) at sync.c

	bpfProgKprobeSync, err := bpfModule.GetProgram("ksys_sync")
	if err != nil {
		Error(err)
	}

	// attach eBPF program to the kprobe and get an eBPF link
	bpfLinkKprobeSync, err := bpfProgKprobeSync.AttachKprobe("ksys_sync")
	if err != nil {
		Error(err)
	}

	bpfHashMap, err := bpfModule.GetMap("hashmap")
	if err != nil {
		Error(err)
	}

	// TRACEPOINT:
	// sys_enter_sync (/sys/kernel/debug/tracing/events/syscalls/sys_enter_sync)

	bpfProgTpSync, err := bpfModule.GetProgram("tracepoint__sys_enter_sync")
	if err != nil {
		Error(err)
	}

	// attach eBPF program to the tracepoint and get an eBPF link
	bpfLinkTpSync, err := bpfProgTpSync.AttachTracepoint(
		"syscalls", "sys_enter_sync",
	)
	if err != nil {
		Error(err)
	}

	//
	// END OF EXAMPLES
	//

	eventsChannel := make(chan []byte)
	lostChannel := make(chan uint64)

	// initialize an eBPF perf buffer to receive events
	bpfPerfBuffer, err := bpfModule.InitPerfBuf(
		"perfbuffer", eventsChannel, lostChannel, 1,
	)
	if err != nil {
		Error(err)
	}

	// start eBPF perf buffer event polling
	bpfPerfBuffer.Start()

	// signal handling
	ctx, stop := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM,
	)
	defer stop()

	// event machine

	fmt.Println("Listening for events, <Ctrl-C> or or SIG_TERM to end it.")
	fmt.Println("Tip: execute \"sync\" command somewhere =)")

LOOP:
	for {
		select {
		case dataRaw := <-eventsChannel:
			data := parseEvent(dataRaw)
			printEvent(data)

			// EXAMPLE: eBPF HASHMAP. For EventKprobeSync only: use perfbuffer
			// event as a trigger and pick data from the hashmap as well (data
			// is indexed by pid)

			switch data.Origin { // check for specific eBPF event received
			case EventKprobeSync: // if event is "sync" (kprobe)

				// pick bytes from the eBPF hashmap
				tgid := uint32(data.Tgid)
				dataRawFromMap, err := bpfHashMap.GetValue(unsafe.Pointer(&tgid))
				bpfHashMap.DeleteKey(unsafe.Pointer(&tgid)) // cleanup if entry exists
				if err != nil {
					Warning(err)
					continue
				}

				dataFromMap := parseEvent(dataRawFromMap)
				dataFromMap.Origin = EventKprobeSyncMap // change event origin
				printEvent(dataFromMap)
			}

			// END OF EXAMPLE

		case lostEvents := <-lostChannel:
			fmt.Fprintf(os.Stdout, "lost %d events\n", lostEvents)

		case <-ctx.Done():
			break LOOP
		}
	}

	// cleanup
	fmt.Println("Cleaning up")

	err = bpfLinkKprobeSync.Destroy()
	if err != nil {
		Error(err)
	}
	err = bpfLinkTpSync.Destroy()
	if err != nil {
		Error(err)
	}

	os.Exit(0)
}

func parseEvent(raw []byte) goData {
	var err error
	var dt data

	buffer := bytes.NewBuffer(raw)
	err = binary.Read(buffer, binary.LittleEndian, &dt)
	if err != nil {
		Warning(err)
		return goData{}
	}

	goData := goData{
		StartTime: uint(dt.StartTime),
		Pid:       uint(dt.Pid),
		Tgid:      uint(dt.Tgid),
		Ppid:      uint(dt.Ppid),
		Uid:       uint(dt.Uid),
		Gid:       uint(dt.Gid),
		Comm:      string(bytes.TrimRight(dt.Comm[:], "\x00")),
		Origin:    NewEventType(dt.Origin),
	}

	return goData
}

func printEvent(goData goData) {
	fmt.Printf(
		"(origin: %s) %s (pid: %d, tgid: %d, ppid: %d, uid: %d, gid: %d)\n",
		goData.Origin,
		goData.Comm,
		goData.Pid,
		goData.Tgid,
		goData.Ppid,
		goData.Uid,
		goData.Gid,
	)
}

func Warning(err error) {
	_, fn, line, _ := runtime.Caller(1)
	log.Printf("WARNING: %s:%d %v\n", fn, line, err)
}

func Error(err error) {
	_, fn, line, _ := runtime.Caller(1)
	log.Printf("ERROR: %s:%d %v\n", fn, line, err)
	os.Exit(1)
}
