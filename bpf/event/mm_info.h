#include "../vmlinux/vmlinux.h"
#include "../../libbpf/src/bpf_helpers.h"
#include "../../libbpf/src/bpf_tracing.h"
#include "../../libbpf/src/bpf_core_read.h"
#include "eoom.h"

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} oom_mm_info SEC(".maps");

static inline int get_task_mm_info(struct mm_struct *mm)
{
    struct task_mm_info *mm_info;
    mm_info = bpf_ringbuf_reserve(&oom_mm_info, sizeof(*mm_info), 0);
    if (mm_info == NULL)
        return -1;

    /*获取虚拟地址空间大小（进程整体可寻址的虚拟地址范围）*/
    mm_info->task_size = BPF_CORE_READ(mm, task_size);
    /*获取虚拟地址空间大小 (实际被进程所占用的虚拟内存大小) 页面计算*/
    mm_info->total_vm = BPF_CORE_READ(mm, total_vm);
    /* hiwater_rss：进程历史上使用的最大物理内存大小，以页面计算 */
    mm_info->hiwater_rss = BPF_CORE_READ(mm, hiwater_rss);
    /* hiwater_vm：进程历史上使用的最大虚拟内存大小，以页面计算 */
    mm_info->hiwater_vm = BPF_CORE_READ(mm, hiwater_vm);
    /*locked_vm：进程当前锁定的内存大小，以页面计算*/
    mm_info->locked_vm = BPF_CORE_READ(mm, locked_vm);
    /*data_vm、exec_vm、stack_vm：进程当前数据段、代码段和堆栈的大小，以页面计算*/
    mm_info->data_vm = BPF_CORE_READ(mm, data_vm);
    mm_info->exec_vm = BPF_CORE_READ(mm, exec_vm);
    mm_info->stack_vm = BPF_CORE_READ(mm, stack_vm);

    bpf_ringbuf_submit(mm_info, 0);
    return 0;
}