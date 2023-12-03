#include "../vmlinux/vmlinux.h"
#include "../../libbpf/src/bpf_helpers.h"
#include "../../libbpf/src/bpf_tracing.h"
#include "../../libbpf/src/bpf_core_read.h"
#include "eoom.h"

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} oom_ns_info SEC(".maps");

static inline int
get_task_namespace_info(struct task_struct *ts)
{
    struct task_ns_info *ns_info;
    ns_info = bpf_ringbuf_reserve(&oom_ns_info, sizeof(*ns_info), 0);
    if (ns_info == NULL)
        return -1;

    // 获取当前进程父进程
    struct task_struct *parent_task = BPF_CORE_READ(ts, real_parent);
    u64 tgid = bpf_get_current_pid_tgid();
    u64 ugid = bpf_get_current_uid_gid();

    ns_info->cgroup_id = bpf_get_current_cgroup_id();
    ns_info->host_tid = tgid;
    ns_info->host_pid = tgid >> 32;
    ns_info->host_ppid = BPF_CORE_READ(parent_task, tgid);

    // 获取进程命名空间信息
    struct nsproxy *namespaceproxy = BPF_CORE_READ(ts, nsproxy);
    // 获取子进程命名空间
    struct pid_namespace *pid_ns_children = BPF_CORE_READ(namespaceproxy, pid_ns_for_children);
    // 获取子进程命名空间的层级
    unsigned int level = BPF_CORE_READ(pid_ns_children, level);

    // 获取当前进程的 level 层进程 PID 信息
    ns_info->tid = BPF_CORE_READ(ts, thread_pid, numbers[level].nr);
    // 获取进程组的 level 层进程 PID 信息
    ns_info->pid = BPF_CORE_READ(ts, group_leader, thread_pid, numbers[level].nr);

    // 获取父进程命名空间
    struct nsproxy *parent_namespaceproxy = BPF_CORE_READ(parent_task, nsproxy);
    // 获取父进程的子进程命名空间
    struct pid_namespace *parent_pid_ns_children =
        BPF_CORE_READ(parent_namespaceproxy, pid_ns_for_children);
    // 获取父进程的子进程命名空间层级
    unsigned int parent_level = BPF_CORE_READ(parent_pid_ns_children, level);
    // 获取父进程组的 level 层进程 PID 信息
    ns_info->ppid = BPF_CORE_READ(parent_task, group_leader, thread_pid,
                                  numbers[parent_level].nr);

    // 获取当前命名空间的 inode 标识号
    ns_info->cgroup_ns_id = BPF_CORE_READ(namespaceproxy, cgroup_ns, ns.inum);
    // IPC 命名空间（IPC Namespace）的 inode 号
    ns_info->ipc_ns_id = BPF_CORE_READ(namespaceproxy, ipc_ns, ns.inum);
    // 网络命名空间的 inode 号
    ns_info->net_ns_id = BPF_CORE_READ(namespaceproxy, net_ns, ns.inum);
    // 挂载名命名空间的 inode 号
    ns_info->mount_ns_id = BPF_CORE_READ(namespaceproxy, mnt_ns, ns.inum);
    // 进程 ID 命名空间的 inode 号
    ns_info->pid_ns_id =
        BPF_CORE_READ(namespaceproxy, pid_ns_for_children, ns.inum);
    // 时间命名空间的 inode 号
    ns_info->time_ns_id = BPF_CORE_READ(namespaceproxy, time_ns, ns.inum);
    // 用户组命名空间的 inode 号
    ns_info->user_ns_id = BPF_CORE_READ(namespaceproxy, cgroup_ns, ns.inum);
    // UTS 命名空间的 inode 号
    ns_info->uts_ns_id = BPF_CORE_READ(namespaceproxy, uts_ns, ns.inum);

    bpf_ringbuf_submit(ns_info, 0);
    return 0;
}