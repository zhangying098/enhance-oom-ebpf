#include "vmlinux/vmlinux.h"
#include "../libbpf/src/bpf_helpers.h"
#include "../libbpf/src/bpf_tracing.h"
#include "../libbpf/src/bpf_core_read.h"

#include "event/eoom.h"
#include "event/mm_info.h"
#include "event/namespace_info.h"

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} oom_event SEC(".maps");

static inline bool is_memcg_oom(struct oom_control *oc)
{
    return oc->memcg != NULL;
}

SEC("kprobe/__oom_kill_process")
int __oom_kill_process_entry(struct pt_regs *ctx)
{
    u64 tgid = 0;
    nodemask_t *nodemask;
    struct task_struct *victim;
    struct mm_struct *mm;
    struct fdtable *fdt;
    struct files_struct *files;

    tgid = bpf_get_current_pid_tgid();
    victim = (struct task_struct *)PT_REGS_PARM1(ctx);
    mm = BPF_CORE_READ(victim, mm);
    files = BPF_CORE_READ(victim, files);
    fdt = BPF_CORE_READ(files, fdt);

    get_task_mm_info(mm);
    get_task_namespace_info(victim);

    return 0;
}

SEC("kprobe/out_of_memory")
int out_of_memory_entry(struct pt_regs *ctx)
{
    struct task_oom_info *info;
    struct oom_control *oc;

    oc = (struct oom_control *)PT_REGS_PARM1(ctx);
    if (is_memcg_oom(oc))
    {
        return 0;
    }

    u64 tgid = bpf_get_current_pid_tgid();

    info = bpf_ringbuf_reserve(&oom_event, sizeof(*info), 0);
    if (info == NULL)
        return -1;

    info->pid = (u32)tgid;
    bpf_get_current_comm(info->comm, sizeof(info->comm));

    bpf_ringbuf_submit(info, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";