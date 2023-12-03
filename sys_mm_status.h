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

#define BUFFER_SIZE 1024

/* 收集 ps -aux 信息*/
static inline void get_ps_aux_info(FILE *logfile, char *timeinfo, char *hostname)
{
    FILE *fp;
    char buffer[BUFFER_SIZE];
    // 执行 free 命令并读取输出
    fp = popen("ps -aux", "r");
    if (fp == NULL)
    {
        fprintf(stderr, "无法执行 ps -aux 命令 \n");
        exit(1);
    }

    // 逐行读取 ps -aux 输出并写入 log 文件
    fprintf(logfile, "%s %s: === Output of ps -aux === \n", timeinfo, hostname);
    while (fgets(buffer, BUFFER_SIZE, fp) != NULL)
    {
        fprintf(logfile, "%s", buffer);
    }

    pclose(fp);
    return;
}

/* 收集 /proc/meminfo 信息*/
static inline void get_proc_info(FILE *logfile, char *timeinfo, char *hostname, char *filepath)
{
    FILE *fp;
    char buffer[BUFFER_SIZE];

    fp = fopen(filepath, "r");
    if (fp == NULL)
    {
        fprintf(stderr, "无法打开 %s 文件 \n", filepath);
        exit(1);
    }

    fprintf(logfile, "%s %s: === Output of %s === \n", timeinfo, hostname, filepath);
    while (fgets(buffer, BUFFER_SIZE, fp) != NULL)
    {
        fprintf(logfile, "%s", buffer);
    }

    fclose(fp);
    return;
}

static int get_sys_mm_status()
{
    time_t rawtime;
    struct tm *timeinfo;
    char raw_time[80];
    char hostname[256];

    time(&rawtime);
    timeinfo = localtime(&rawtime);
    gethostname(hostname, sizeof(hostname));
    strftime(raw_time, 80, "%b %e %T", timeinfo);

    FILE *logfile = fopen("/var/log/message", "a");
    if (logfile == NULL)
    {
        fprintf(stderr, "无法打开日志文件 /var/log/mesage \n");
        return errno;
    }

    get_ps_aux_info(logfile, raw_time, hostname);
    get_proc_info(logfile, raw_time, hostname, "/proc/meminfo");
    get_proc_info(logfile, raw_time, hostname, "/proc/slabinfo");

    fclose(logfile);
    return 0;
}
