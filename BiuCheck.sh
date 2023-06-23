#!/bin/bash

 
# 字体颜色变量
RED_COLOR='\E[1;31m'
GREEN_COLOR='\E[1;32m'
YELLOW_COLOR='\E[1;33m'
BLUE_COLOR='\E[1;34m'
PINK_COLOR='\E[1;35m'
RES='\E[0m'
 

_red() {
    printf '\033[0;31;31m%b\033[0m' "$1"
}

_green() {
    printf '\033[0;31;32m%b\033[0m' "$1"
}

_yellow() {
    printf '\033[0;31;33m%b\033[0m' "$1"
}

_blue() {
    printf '\033[0;31;36m%b\033[0m' "$1"
}

_exists() {
    local cmd="$1"
    if eval type type > /dev/null 2>&1; then
        eval type "$cmd" > /dev/null 2>&1
    elif command > /dev/null 2>&1; then
        command -v "$cmd" > /dev/null 2>&1
    else
        which "$cmd" > /dev/null 2>&1
    fi
    local rt=$?
    return ${rt}
}

get_opsy() {
    [ -f /etc/redhat-release ] && awk '{print $0}' /etc/redhat-release && return
    [ -f /etc/os-release ] && awk -F'[= "]' '/PRETTY_NAME/{print $3,$4,$5}' /etc/os-release && return
    [ -f /etc/lsb-release ] && awk -F'[="]+' '/DESCRIPTION/{print $2}' /etc/lsb-release && return
}

next() {
    printf "%-70s\n" "-" | sed 's/\s/-/g'
}

# 防火墙检查项
CheckFirewalld(){
	if systemctl is-active firewalld &>/dev/null ;then
		firewalldStatus=$(_red "Disabled")
	else
		firewalldStatus=$(_green "Enabled")
	fi
}


# SSH检查项
CheckSSH(){

	# ssh端口
	ssh_portNum=`grep ^Port /etc/ssh/sshd_config | wc -l`
	if [ $ssh_portNum -eq 0 ];then
		ssh_port=$(_red "22")
	else
		if [ $ssh_portNum -eq 1 ];then
			ssh_port=`grep ^Port /etc/ssh/sshd_config | awk '{print $2}'`
		else
			ssh_port="多个配置项 `grep ^Port /etc/ssh/sshd_config | awk '{print $2}' | xargs`"
		fi
	fi
	
	# ssh的tcp转发，默认允许
	value=$(grep -E ^AllowTcpForwarding /etc/ssh/sshd_config | awk '{print $2}')
	if [ "$value" = "no" ]; then
			AllowTcpForwardingStS=$(_green "Disabled")
		else
			AllowTcpForwardingStS=$(_red "Enabled")
	fi
	
	# ssh的空密码登陆，默认拒绝
	value=$(grep -E ^PermitEmptyPasswords /etc/ssh/sshd_config | awk '{print $2}')
	if [ "$value" = "yes" ]; then
			PermitEmptyPasswordsStS=$(_red "Enabled")
		else
			PermitEmptyPasswordsStS=$(_green "Disabled")
	fi
	
	# ssh的root登陆，默认禁止
	value=$(grep -E ^PermitRootLogin /etc/ssh/sshd_config | awk '{print $2}')
	if [ "$value" = "yes" ]; then
			PermitRootLoginStS=$(_red "Enabled")
		else
			PermitRootLoginStS=$(_green "Disabled")
	fi

	# ssh的dns解析，默认打开
	value=$(grep -E ^UseDNS /etc/ssh/sshd_config | awk '{print $2}')
	if [ "$value" = "no" ]; then
			UseDNSStS=$(_green "Disabled")
		else
			UseDNSStS=$(_red "Enabled")
	fi
}


calc_size() {
    local raw=$1
    local total_size=0
    local num=1
    local unit="KB"
    if ! [[ ${raw} =~ ^[0-9]+$ ]] ; then
        echo ""
        return
    fi
    if [ "${raw}" -ge 1073741824 ]; then
        num=1073741824
        unit="TB"
    elif [ "${raw}" -ge 1048576 ]; then
        num=1048576
        unit="GB"
    elif [ "${raw}" -ge 1024 ]; then
        num=1024
        unit="MB"
    elif [ "${raw}" -eq 0 ]; then
        echo "${total_size}"
        return
    fi
    total_size=$( awk 'BEGIN{printf "%.1f", '$raw' / '$num'}' )
    echo "${total_size} ${unit}"
}

check_virt(){
    _exists "dmesg" && virtualx="$(dmesg 2>/dev/null)"
    if _exists "dmidecode"; then
        sys_manu="$(dmidecode -s system-manufacturer 2>/dev/null)"
        sys_product="$(dmidecode -s system-product-name 2>/dev/null)"
        sys_ver="$(dmidecode -s system-version 2>/dev/null)"
    else
        sys_manu=""
        sys_product=""
        sys_ver=""
    fi
    if   grep -qa docker /proc/1/cgroup; then
        virt="Docker"
    elif grep -qa lxc /proc/1/cgroup; then
        virt="LXC"
    elif grep -qa container=lxc /proc/1/environ; then
        virt="LXC"
    elif [[ -f /proc/user_beancounters ]]; then
        virt="OpenVZ"
    elif [[ "${virtualx}" == *kvm-clock* ]]; then
        virt="KVM"
    elif [[ "${sys_product}" == *KVM* ]]; then
        virt="KVM"
    elif [[ "${cname}" == *KVM* ]]; then
        virt="KVM"
    elif [[ "${cname}" == *QEMU* ]]; then
        virt="KVM"
    elif [[ "${virtualx}" == *"VMware Virtual Platform"* ]]; then
        virt="VMware"
    elif [[ "${sys_product}" == *"VMware Virtual Platform"* ]]; then
        virt="VMware"
    elif [[ "${virtualx}" == *"Parallels Software International"* ]]; then
        virt="Parallels"
    elif [[ "${virtualx}" == *VirtualBox* ]]; then
        virt="VirtualBox"
    elif [[ -e /proc/xen ]]; then
        if grep -q "control_d" "/proc/xen/capabilities" 2>/dev/null; then
            virt="Xen-Dom0"
        else
            virt="Xen-DomU"
        fi
    elif [ -f "/sys/hypervisor/type" ] && grep -q "xen" "/sys/hypervisor/type"; then
        virt="Xen"
    elif [[ "${sys_manu}" == *"Microsoft Corporation"* ]]; then
        if [[ "${sys_product}" == *"Virtual Machine"* ]]; then
            if [[ "${sys_ver}" == *"7.0"* || "${sys_ver}" == *"Hyper-V" ]]; then
                virt="Hyper-V"
            else
                virt="Microsoft Virtual Machine"
            fi
        fi
    else
        virt="Dedicated"
    fi
}



# Get System information
get_system_info() {
    cname=$( awk -F: '/model name/ {name=$2} END {print name}' /proc/cpuinfo | sed 's/^[ \t]*//;s/[ \t]*$//' )
    cores=$( awk -F: '/processor/ {core++} END {print core}' /proc/cpuinfo )
    freq=$( awk -F'[ :]' '/cpu MHz/ {print $4;exit}' /proc/cpuinfo )
    ccache=$( awk -F: '/cache size/ {cache=$2} END {print cache}' /proc/cpuinfo | sed 's/^[ \t]*//;s/[ \t]*$//' )
    cpu_aes=$( grep -i 'aes' /proc/cpuinfo )
    cpu_virt=$( grep -Ei 'vmx|svm' /proc/cpuinfo )
    tram=$( LANG=C; free | awk '/Mem/ {print $2}' )
    tram=$( calc_size $tram )
    uram=$( LANG=C; free | awk '/Mem/ {print $3}' )
    uram=$( calc_size $uram )
    swap=$( LANG=C; free | awk '/Swap/ {print $2}' )
    swap=$( calc_size $swap )
    uswap=$( LANG=C; free | awk '/Swap/ {print $3}' )
    uswap=$( calc_size $uswap )
    up=$( awk '{a=$1/86400;b=($1%86400)/3600;c=($1%3600)/60} {printf("%d days, %d hour %d min\n",a,b,c)}' /proc/uptime )
    if _exists "w"; then
        load=$( LANG=C; w | head -1 | awk -F'load average:' '{print $2}' | sed 's/^[ \t]*//;s/[ \t]*$//' )
    elif _exists "uptime"; then
        load=$( LANG=C; uptime | head -1 | awk -F'load average:' '{print $2}' | sed 's/^[ \t]*//;s/[ \t]*$//' )
    fi
    opsy=$( get_opsy )
    arch=$( uname -m )
    if _exists "getconf"; then
        lbit=$( getconf LONG_BIT )
    else
        echo ${arch} | grep -q "64" && lbit="64" || lbit="32"
    fi
    kern=$( uname -r )
    disk_total_size=$( LANG=C; df -t simfs -t ext2 -t ext3 -t ext4 -t btrfs -t xfs -t vfat -t ntfs -t swap --total 2>/dev/null | grep total | awk '{ print $2 }' )
    disk_total_size=$( calc_size $disk_total_size )
    disk_used_size=$( LANG=C; df -t simfs -t ext2 -t ext3 -t ext4 -t btrfs -t xfs -t vfat -t ntfs -t swap --total 2>/dev/null | grep total | awk '{ print $3 }' )
    disk_used_size=$( calc_size $disk_used_size )
    tcpctrl=$( sysctl net.ipv4.tcp_congestion_control | awk -F ' ' '{print $3}' )
}

print_system_info() {
	echo -e " Hostname       \t: $(_blue `uname -n`)"
	address=$(ip addr | grep inet | grep -v "inet6" | grep -v "127.0.0.1" | awk '{ print $2; }' | tr '\n' '\t' )
    if [ -n "$cname" ]; then
        echo -e " CPU Model          \t: $(_blue "$cname")"
    else
        echo -e " CPU Model          \t: $(_blue "CPU model not detected")"
    fi
    if [ -n "$freq" ]; then
        echo -e " CPU Cores          \t: $(_blue "$cores @ $freq MHz")"
    else
        echo -e " CPU Cores          \t: $(_blue "$cores")"
    fi
    if [ -n "$cpu_aes" ]; then
        echo -e " AES-NI             \t: $(_green "Enabled")"
    else
        echo -e " AES-NI             \t: $(_red "Disabled")"
    fi
    if [ -n "$cpu_virt" ]; then
        echo -e " VM-x/AMD-V         \t: $(_green "Enabled")"
    else
        echo -e " VM-x/AMD-V         \t: $(_red "Disabled")"
    fi
    echo -e " Total Disk         \t: $(_yellow "$disk_total_size") $(_blue "($disk_used_size Used)")"
    echo -e " Total Mem          \t: $(_yellow "$tram") $(_blue "($uram Used)")"
    if [ "$swap" != "0" ]; then
        echo -e " Total Swap        \t: $(_blue "$swap ($uswap Used)")"
    fi
    echo -e " System uptime     \t: $(_blue "$up")"
    echo -e " Load average      \t: $(_blue "$load")"
    echo -e " OS                \t: $(_blue "$opsy")"
    echo -e " Arch              \t: $(_blue "$arch ($lbit Bit)")"
    echo -e " Kernel            \t: $(_blue "$kern")"
    echo -e " TCP CC             \t: $(_yellow "$tcpctrl")"
    echo -e " Virtualization     \t: $(_blue "$virt")"
    echo -e " Private IPv4      \t: $(_blue "$address")"
    # echo -e " Public IPv4        \t: $(_blue `curl -s --connect-timeout 3 ifconfig.me`)"
    echo -e " Public IPv4     	: $(_blue `curl -s --connect-timeout 3 ifconfig.me`)"
}

maliciousProcesses() {
	ps -ef | grep zombie | grep -v grep
	if [ $? == 1 ];then
		zombieProcesses="$(_blue "无僵尸进程")"
	else
		zombieProcesses="$(_red ">>>有僵尸进程------[需调整]")"
	fi
	ps -ef | grep cdn | grep -v grep
	if [ $? == 1 ];then
		cdnProcesses="$(_blue "无挖矿进程")"
	else
		cdnProcesses= "$(_red ">>>有挖矿进程------[需调整]")"
	fi
}




# 函数运行
CheckSSH
CheckFirewalld



# 输出内容
clear

echo "-------------------- A BiuCheck.sh Script By Gavin2love -------------------"
echo -e " Version        \t: $(_green v2023-06-23)"
echo -e " Usage 		 \t: $(_red "github.com/gavin2love/BiuCheck")"

echo
echo "-------------------- 系统信息确认 -------------------"
get_system_info
check_virt
print_system_info



echo
echo "-------------------- SSH服务检查 -------------------"
echo -e " SSH-端口       \t: $ssh_port" 
echo -e " SSH-TCP转发    \t: $AllowTcpForwardingStS" 
echo -e " SSH-空密码登录 \t: $PermitEmptyPasswordsStS" 
echo -e " SSH-root登录   \t: $PermitRootLoginStS" 
echo -e " SSH-DNS解析    \t: $UseDNSStS" 

echo
echo "-------------------- 基础服务检查 -------------------"
echo -e " Firewalld状态  \t: ${firewalldStatus}" 

echo
echo "-------------------- 用户用户组检查 ---------------"
echo  "===> 在线用户:"
w | tail -n +2
echo "===> 系统特权用户:"
awk -F: '$3==0 {print $1}' /etc/passwd

echo
echo "-------------------- 恶意进程检查 -----------------"
maliciousProcesses
echo -e " 僵尸进程       \t: $zombieProcesses" 
echo -e " 挖矿进程       \t: $cdnProcesses" 

echo
echo -e "-------------------- $(_yellow "CPU")高占用排行top10 ---------------"
ps -eo user,pid,pcpu,pmem,args --sort=-pcpu | head -n 10

echo
echo -e "-------------------- $(_yellow "Mem")高占用排行top10 ---------------"
ps -eo user,pid,pcpu,pmem,args --sort=-pmem | head -n 10

echo
echo -e "$(_green 检查结束.done~~~)"
echo
