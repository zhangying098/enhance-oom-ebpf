#!/bin/bash
# 定义配置项
CONFIG_KEY="vm.overcommit_memory"
CONFIG_VALUE="1"
EXPECTED_VALUE="0"
CONFIG="${CONFIG_KEY} = ${CONFIG_VALUE}"
EXPECTED_CONFIG="${CONFIG_KEY} = ${EXPECTED_VALUE}"

free_memory=$(free -m | awk 'NR==2{print $4}')

function modify_config()
{
    switch=$1
    if [ "$switch" == "enable" ]; then

        sudo sed -i "s/^${CONFIG_KEY}[[:space:]]*=.*/${CONFIG_KEY} = ${CONFIG_VALUE}/" /etc/sysctl.conf > /dev/null 2>&1
        # 检查 /etc/sysctl.conf 文件中是否存在指定的配置项
        if ! grep -q "^${CONFIG_KEY}[[:space:]]*=[[:space:]]*${CONFIG_VALUE}" /etc/sysctl.conf; then
            # 不存在，则追加到文件末尾
            echo "${CONFIG}" | sudo tee -a /etc/sysctl.conf > /dev/null
        fi
    fi

    if [ "${switch}" == "disable" ]; then
        if grep -q "^${CONFIG_KEY}[[:space:]]*=[[:space:]]*${CONFIG_VALUE}" /etc/sysctl.conf; then
            sudo sed -i "s/^${CONFIG_KEY}[[:space:]]*=.*/${CONFIG_KEY} = ${EXPECTED_VALUE}/" /etc/sysctl.conf
        fi
    fi
}

function reset()
{
    swapon -a
    modify_config "disable"
    sudo sysctl -p > /dev/null 2>&1
}

function benchmark()
{
    swapoff -a
    modify_config "enable"
    sudo sysctl -p > /dev/null 2>&1
    echo "start redis oom benchmark, waiting for minutes..."
    redis-server --test-memory $((free_memory * 4)) > /dev/null 2>&1
}

reset
benchmark
reset



