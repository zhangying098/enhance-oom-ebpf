#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/sysmacros.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <asm/types.h>
#include <stdarg.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>

/* for bpf*/
#include <linux/bpf.h>
#include <bpf/bpf.h>
/*  bpf end */

#include "bpf/eoom.skel.h"
#include "common_u.h"
#include "sys_mm_status.h"

static unsigned int running = true;

static struct eoom_bpf *skel;
static void *mm_mapfd;
static void *ns_mapfd;
static void *oom_mapfd;

static inline void memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new))
    {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        exit(1);
    }
}

static void print_oom_info(enum oom_info_type type, void *data)
{
    struct task_mm_info *mm_info;
    struct task_ns_info *ns_info;

    time_t rawtime;
    struct tm *timeinfo;
    char buffer[80];
    char hostname[256];

    time(&rawtime);
    timeinfo = localtime(&rawtime);
    gethostname(hostname, sizeof(hostname));
    strftime(buffer, 80, "%b %e %T", timeinfo);

    FILE *logfile = fopen("/var/log/message", "a");
    if (logfile == NULL)
    {
        fprintf(stderr, "无法打开日志文件 /var/log/mesage \n");
        return;
    }

    if (type == OOM_INFO_TYPE_MM)
    {
        mm_info = (struct task_mm_info *)data;
        strftime(buffer, 80, "%b %e %T", timeinfo);

        fprintf(logfile, "%s %s: Victim task mem info: \n", buffer, hostname);
        fprintf(logfile, "%s %s: task_size: %lu \n", buffer, hostname, mm_info->task_size);
        fprintf(logfile, "%s %s: total_vm: %lu \n", buffer, hostname, mm_info->total_vm);
        fprintf(logfile, "%s %s: hiwater_rss: %lu \n", buffer, hostname, mm_info->hiwater_rss);
        fprintf(logfile, "%s %s: hiwater_vm: %lu \n", buffer, hostname, mm_info->hiwater_vm);
        fprintf(logfile, "%s %s: data_vm: %lu \n", buffer, hostname, mm_info->data_vm);
        fprintf(logfile, "%s %s: exec_vm: %lu \n", buffer, hostname, mm_info->exec_vm);
        fprintf(logfile, "%s %s: stack_vm: %lu \n", buffer, hostname, mm_info->stack_vm);
        return;
    }
    else if (type == OOM_INFO_TYPE_NS)
    {
        ns_info = (struct task_ns_info *)data;
        strftime(buffer, 80, "%b %e %T", timeinfo);

        fprintf(logfile, "%s %s: Victim task namespace info: \n", buffer, hostname);
        fprintf(logfile, "%s %s: cgroup_id: %llu \n", buffer, hostname, ns_info->cgroup_id);
        fprintf(logfile, "%s %s: host_tid: %u \n", buffer, hostname, ns_info->host_tid);
        fprintf(logfile, "%s %s: host_pid: %u \n", buffer, hostname, ns_info->host_pid);
        fprintf(logfile, "%s %s: host_ppid: %u \n", buffer, hostname, ns_info->host_ppid);
        fprintf(logfile, "%s %s: tid: %u \n", buffer, hostname, ns_info->tid);
        fprintf(logfile, "%s %s: pid: %u \n", buffer, hostname, ns_info->pid);
        fprintf(logfile, "%s %s: ppid: %u \n", buffer, hostname, ns_info->ppid);
        fprintf(logfile, "%s %s: uid: %u \n", buffer, hostname, ns_info->uid);
        fprintf(logfile, "%s %s: gid: %u \n", buffer, hostname, ns_info->gid);
        fprintf(logfile, "%s %s: cgroup_ns_id: %u \n", buffer, hostname, ns_info->cgroup_ns_id);
        fprintf(logfile, "%s %s: ipc_ns_id: %u \n", buffer, hostname, ns_info->ipc_ns_id);
        fprintf(logfile, "%s %s: net_ns_id: %u \n", buffer, hostname, ns_info->net_ns_id);
        fprintf(logfile, "%s %s: mount_ns_id: %u \n", buffer, hostname, ns_info->mount_ns_id);
        fprintf(logfile, "%s %s: pid_ns_id: %u \n", buffer, hostname, ns_info->pid_ns_id);
        fprintf(logfile, "%s %s: time_ns_id: %u \n", buffer, hostname, ns_info->time_ns_id);
        fprintf(logfile, "%s %s: user_ns_id: %u \n", buffer, hostname, ns_info->user_ns_id);
        fprintf(logfile, "%s %s: uts_ns_id: %u \n", buffer, hostname, ns_info->uts_ns_id);
        return;
    }

    pclose(logfile);
    return;
}

static int oom_monitor_evhandler(void *ctx, void *data, size_t data_sz)
{
    int ret = 0;
    struct task_oom_info *oom_info = data;
    ret = get_sys_mm_status();
    return ret;
}

static int mm_monitor_evhandler(void *ctx, void *data, size_t data_sz)
{
    struct task_mm_info *mm_info = data;
    if (mm_info == NULL)
        return -1;
    print_oom_info(OOM_INFO_TYPE_MM, (void *)mm_info);
    return errno;
}

static int ns_monitor_evhandler(void *ctx, void *data, size_t data_sz)
{
    struct task_ns_info *ns_info = data;
    if (ns_info == NULL)
        return -1;
    print_oom_info(OOM_INFO_TYPE_NS, (void *)ns_info);
    return errno;
}

static int do_monitor()
{
    int ret = 0;

    while (running)
    {
        ret = ring_buffer__poll(oom_mapfd, 10000); /* timeout 100ms*/
        if (ret < 0)
        {
            printf("Error polling oom ring buffer:%d\n", ret);
            return ret;
        }
        ret = ring_buffer__poll(mm_mapfd, 10000); /* timeout 100ms*/
        if (ret < 0)
        {
            printf("Error polling memory ring buffer:%d\n", ret);
            return ret;
        }
        ret = ring_buffer__poll(ns_mapfd, 10000); /* timeout 100ms*/
        if (ret < 0)
        {
            printf("Error polling namespace ring buffer:%d\n", ret);
            return ret;
        }
    }
    return 0;
}

static inline void sig_handler(int sig)
{
    running = 0;
}

static int load_skel()
{
    int ret;
    skel = eoom_bpf__open_and_load();
    if (!skel)
    {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return -1;
    }

    ret = eoom_bpf__attach(skel);
    if (ret)
    {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        return -1;
    }

    oom_mapfd = ring_buffer__new(bpf_map__fd(skel->maps.oom_event), oom_monitor_evhandler, NULL, NULL);
    if (libbpf_get_error(oom_mapfd))
    {
        fprintf(stderr, "Failed to create oom buffer\n");
        return -1;
    }

    mm_mapfd = ring_buffer__new(bpf_map__fd(skel->maps.oom_mm_info), mm_monitor_evhandler, NULL, NULL);
    if (libbpf_get_error(mm_mapfd))
    {
        fprintf(stderr, "Failed to create memory buffer\n");
        return -1;
    }

    ns_mapfd = ring_buffer__new(bpf_map__fd(skel->maps.oom_ns_info), ns_monitor_evhandler, NULL, NULL);
    if (libbpf_get_error(ns_mapfd))
    {
        fprintf(stderr, "Failed to create namespace buffer\n");
        return -1;
    }

    return ret;
}

int main(int argc, char **argv)
{
    int ret;
    memlock_rlimit();
    ret = load_skel();
    if (ret < 0)
        goto cleanup;

    printf("Tracing oom event... Hit Ctrl-C to end.\n\n");
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    ret = do_monitor();
cleanup:
    ring_buffer__free(ns_mapfd);
    ring_buffer__free(mm_mapfd);
    eoom_bpf__destroy(skel);
    return ret;
}