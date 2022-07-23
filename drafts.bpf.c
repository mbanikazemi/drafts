//go:build exclude

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16
#define PERF_EVENT_ARRAY_MAX_ENTRIES 1024
#define HASHMAP_MAX_ENTRIES 1024

//
// EXAMPLES: eBPF map types
//

// PERF_EVENT_ARRAY (used by perfbuffer)

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(max_entries, PERF_EVENT_ARRAY_MAX_ENTRIES);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} perfbuffer SEC(".maps");

// HASHMAP (key/value hash map shared with userland)

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, HASHMAP_MAX_ENTRIES);
	__type(key, u32); // key = pid
	__type(value, struct event_data); // value = event_data
} hashmap SEC(".maps");

// END OF EXAMPLES

//
// internal structures
//

enum origin
{
    EVENT_KPROBE_SYNC = 1,
    EVENT_KPROBE_SYNC_MAP,
    EVENT_TP_SYNC
};

typedef struct task_info {
    u64 start_time;             // task start time
    u32 pid;                    // host process id
    u32 tgid;                   // host thread group id
    u32 ppid;                   // host parent process id
    u32 uid;                    // user id
    u32 gid;                    // group id
    char comm[TASK_COMM_LEN];   // command line
    u32 padding;                // padding
} task_info_t;

// main perfbuffer event structure (sent to userland)
struct event_data {
    struct task_info task;
    u32 origin;                 // eBPF program event generator
} event_data_t;

//
// helper functions
//

// get current task "task_struct" structure
static __always_inline struct task_struct *
get_task_struct()
{
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    return task;
}

// get current task user id
static __always_inline u32
get_uid()
{
    u64 id = bpf_get_current_uid_gid();
    u32 uid = id;
    return uid;
}

// get current task group id
static __always_inline u32
get_gid()
{
    u64 id = bpf_get_current_uid_gid();
    u32 gid = id >> 32;
    return gid;
}

// get current task process id
static __always_inline u32
get_pid()
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    return pid;
}

// get current thread group id
static __always_inline u32
get_tgid()
{
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    return tgid;
}

// get current task parent process id
static __always_inline u32
get_ppid(struct task_struct *child)
{
    struct task_struct *parent;
    parent = BPF_CORE_READ(child, real_parent);
    u32 ptgid = BPF_CORE_READ(parent, tgid);
    return ptgid;
}

//
// internal functions
//

// return an internal structured called task_info with current task information
static __always_inline void
get_task_info(struct task_info *info)
{
    struct task_struct *task = get_task_struct();
    u64 id = bpf_get_current_pid_tgid();

    info->tgid = get_tgid();
    info->pid = get_pid();
    info->uid = get_uid();
    info->gid = get_gid();
    info->ppid = get_ppid(task);

    bpf_probe_read_kernel_str(info->comm, TASK_COMM_LEN, task->comm);
}

// return a structure to be sent through perfbuffer to userland
static __always_inline void
get_event_data(u32 orig, struct task_info *info, struct event_data *data)
{
    data->origin = orig;

    data->task.tgid = info->tgid;
    data->task.pid = info->pid;
    data->task.uid = info->uid;
    data->task.gid = info->gid;
    data->task.ppid = info->ppid;

    __builtin_memcpy(data->task.comm, info->comm, TASK_COMM_LEN);
}

//
// EXAMPLES: eBPF program types (each function is a different eBPF program)
//

// KPROBE:
// SYSCALL_DEFINE0(sync) at sync.c

SEC("kprobe/ksys_sync")
int BPF_KPROBE(ksys_sync)
{
    struct task_info info = {};
    struct event_data data = {};

    get_task_info(&info);
    get_event_data(EVENT_KPROBE_SYNC, &info, &data);

    // EXAMPLE: same information shared with userland in 2 different ways

    // eBPF MAP: save event_data to the hashmap
    bpf_map_update_elem(&hashmap, &info.tgid, &data, BPF_ANY);

    // send a perf event to userland (with event_data)
    bpf_perf_event_output(
        ctx,
        &perfbuffer,
        BPF_F_CURRENT_CPU,
        &data,
        sizeof(data)
    );

    return 0;
}

// TRACEPOINT:
// sys_enter_sync (/sys/kernel/debug/tracing/events/syscalls/sys_enter_sync)

SEC("tracepoint/syscalls/sys_enter_sync")
int tracepoint__sys_enter_sync(struct trace_event_raw_sys_enter *ctx)
{
    struct task_info info = {};
    struct event_data data = {};

    get_task_info(&info);
    get_event_data(EVENT_TP_SYNC, &info, &data);

    // send a perf event to userland (with event_data)
    bpf_perf_event_output(
        ctx,
        &perfbuffer,
        BPF_F_CURRENT_CPU,
        &data,
        sizeof(data)
    );

    return 0;
}

// END OF EXAMPLES