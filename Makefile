CC = clang
CFLAGS = -g -O2 -DBPF_NO_PRESERVE_ACCESS_INDEX -D__TARGET_ARCH_x86
LDFLAGS = -lelf -lbpf

all: eoom

clean:
	rm -rf bpf/eoom.bpf.o bpf/eoom.skel.h eoom eoom.o sys_mm_status.o

bpf/eoom.bpf.o: bpf/eoom.bpf.c
	$(CC) $(CFLAGS) -target bpf -c $< -o $@
	llvm-strip -g $@

bpf/eoom.skel.h: bpf/eoom.bpf.o
	bpftool gen skeleton $< > $@

eoom: eoom.c bpf/eoom.skel.h
	$(CC) $< $(LDFLAGS) -o $@

install: eoom
	# 将可执行文件复制到系统目录
	cp eoom /usr/local/bin/eoom

	# 创建一个 systemd 服务单元文件
	echo "[Unit]" > /etc/systemd/system/eoom.service
	echo "Description=oom log enhance" >> /etc/systemd/system/eoom.service
	echo "" >> /etc/systemd/system/eoom.service
	echo "[Service]" >> /etc/systemd/system/eoom.service
	echo "Type=simple" >> /etc/systemd/system/eoom.service
	echo "ExecStart=/usr/local/bin/eoom" >> /etc/systemd/system/eoom.service
	echo "Restart=always" >> /etc/systemd/system/eoom.service
	echo "" >> /etc/systemd/system/eoom.service
	echo "[Install]" >> /etc/systemd/system/eoom.service
	echo "WantedBy=multi-user.target" >> /etc/systemd/system/eoom.service

	# 重新加载 systemd 管理的守护进程
	systemctl daemon-reload

	# 启用并启动 eoom 服务
	systemctl enable eoom
	systemctl start eoom

uninstall:
	# 停止并禁用 eoom 服务
	systemctl stop eoom
	systemctl disable eoom

	# 删除 eoom 可执行文件和 systemd 服务单元文件
	rm /usr/local/bin/eoom
	rm /etc/systemd/system/eoom.service