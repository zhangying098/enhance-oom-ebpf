#ifndef __EOOM_H__
#define __EOOM_H__

#ifndef MAX_FILENAME_LEN
#define MAX_FILENAME_LEN 32
#endif

#ifndef MAX_COMM_LEN
#define MAX_COMM_LEN 128
#endif

struct task_oom_info
{
    u32 pid;
    char comm[MAX_COMM_LEN];
};

struct task_mm_info
{
    long unsigned int task_size;
    long unsigned int total_vm;
    long unsigned int hiwater_rss;
    long unsigned int hiwater_vm;
    long unsigned int locked_vm;
    long unsigned int data_vm;
    long unsigned int exec_vm;
    long unsigned int stack_vm;
};

struct task_ns_info
{
    long long unsigned int cgroup_id; // cgroup id
    unsigned int host_tid;            // tid in host pid namespace
    unsigned int host_pid;            // pid in host pid namespace
    unsigned int host_ppid;           // ppid in host pid namespace

    unsigned int tid;  // thread id in userspace
    unsigned int pid;  // process id in userspace
    unsigned int ppid; // parent process id in userspace
    unsigned int uid;
    unsigned int gid;

    unsigned int cgroup_ns_id;
    unsigned int ipc_ns_id;
    unsigned int net_ns_id;
    unsigned int mount_ns_id;
    unsigned int pid_ns_id;
    unsigned int time_ns_id;
    unsigned int user_ns_id;
    unsigned int uts_ns_id;
};
#endif