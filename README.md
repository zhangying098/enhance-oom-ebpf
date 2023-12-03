enhance-oom-ebpf
======================================
**Obtain system memory information in the oom scenario**

Building And Installing eoom
======================================
```bash
$ make
$ make install
```

Uninstalling eoom
======================================
```bash
$ make uninstall
```

Example
======================================
**View dumped logs `cat /var/log/message`**

```bash
Dec  8 21:05:20 zhangying-virtual-machine: Victim task namespace info:
Dec  8 21:05:20 zhangying-virtual-machine: cgroup_id: 3338
Dec  8 21:05:20 zhangying-virtual-machine: host_tid: 727
Dec  8 21:05:20 zhangying-virtual-machine: host_pid: 727
Dec  8 21:05:20 zhangying-virtual-machine: host_ppid: 60869
Dec  8 21:05:20 zhangying-virtual-machine: tid: 60884
Dec  8 21:05:20 zhangying-virtual-machine: pid: 60884
Dec  8 21:05:20 zhangying-virtual-machine: ppid: 60869
Dec  8 21:05:20 zhangying-virtual-machine: uid: 0
Dec  8 21:05:20 zhangying-virtual-machine: gid: 0
Dec  8 21:05:20 zhangying-virtual-machine: cgroup_ns_id: 4026531835
Dec  8 21:05:20 zhangying-virtual-machine: ipc_ns_id: 4026531839
Dec  8 21:05:20 zhangying-virtual-machine: net_ns_id: 4026531840
Dec  8 21:05:20 zhangying-virtual-machine: mount_ns_id: 4026531841
Dec  8 21:05:20 zhangying-virtual-machine: pid_ns_id: 4026531836
Dec  8 21:05:20 zhangying-virtual-machine: time_ns_id: 4026531834
Dec  8 21:05:20 zhangying-virtual-machine: user_ns_id: 4026531835
Dec  8 21:05:20 zhangying-virtual-machine: uts_ns_id: 4026531838
Dec  8 21:05:20 zhangying-virtual-machine: Victim task mem info:
Dec  8 21:05:20 zhangying-virtual-machine: task_size: 140737488351232
Dec  8 21:05:20 zhangying-virtual-machine: total_vm: 7352107
Dec  8 21:05:20 zhangying-virtual-machine: hiwater_rss: 1585984
Dec  8 21:05:20 zhangying-virtual-machine: hiwater_vm: 5830
Dec  8 21:05:20 zhangying-virtual-machine: data_vm: 7344787
Dec  8 21:05:20 zhangying-virtual-machine: exec_vm: 2605
Dec  8 21:05:20 zhangying-virtual-machine: stack_vm: 33
Dec  8 22:44:18 zhangying-virtual-machine: === Output of ps -aux ===
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  3.4  0.0 168080  5760 ?        Ss   22:38   0:11 /sbin/init splash
root           2  0.0  0.0      0     0 ?        S    22:38   0:00 [kthreadd]
root           3  0.0  0.0      0     0 ?        I<   22:38   0:00 [rcu_gp]
.....................

Dec  8 22:44:18 zhangying-virtual-machine: === Output of /proc/meminfo ===
MemTotal:        7534128 kB
MemFree:         6112864 kB
MemAvailable:    6072288 kB
.....................

Dec  8 22:44:18 zhangying-virtual-machine: === Output of /proc/slabinfo ===
slabinfo - version: 2.1
# name            <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab> : tunables <limit> <batchcount> <sharedfactor> : slabdata <active_slabs> <num_slabs> <sharedavail>
nf_conntrack         288    288    256   32    2 : tunables    0    0    0 : slabdata      9      9      0
ovl_inode             22     22    728   22    4 : tunables    0    0    0 : slabdata      1      1      0
AF_VSOCK              75     75   1280   25    8 : tunables    0    0    0 : slabdata      3      3      0
......................
```