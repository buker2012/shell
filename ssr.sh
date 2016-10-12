#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

clear
echo
echo "##########################################"
echo "# 一键配置ShadowsocksR for CentOS 7      #"
echo "# Web: http://branit.cc                  #"
echo "# Author: Buker                          #"
echo "##########################################"
echo

#Current folder
cur_dir=`pwd`

# Make sure only root can run our script
rootness(){
    if [[ $EUID -ne 0 ]]; then
       echo "Error: This script must be run as root!" 1>&2
       exit 1
    fi
}

# Disable selinux
disable_selinux(){
    if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        setenforce 0
    fi
}

#Check system
check_sys(){
    local checkType=$1
    local value=$2

    local release=''
    local systemPackage=''

    if [[ -f /etc/redhat-release ]]; then
        release="centos"
        systemPackage="yum"
    elif cat /etc/issue | grep -q -E -i "debian"; then
        release="debian"
        systemPackage="apt"
    elif cat /etc/issue | grep -q -E -i "ubuntu"; then
        release="ubuntu"
        systemPackage="apt"
    elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
        release="centos"
        systemPackage="yum"
    elif cat /proc/version | grep -q -E -i "debian"; then
        release="debian"
        systemPackage="apt"
    elif cat /proc/version | grep -q -E -i "ubuntu"; then
        release="ubuntu"
        systemPackage="apt"
    elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
        release="centos"
        systemPackage="yum"
    fi

    if [[ ${checkType} == "sysRelease" ]]; then
        if [ "$value" == "$release" ]; then
            return 0
        else
            return 1
        fi
    elif [[ ${checkType} == "packageManager" ]]; then
        if [ "$value" == "$systemPackage" ]; then
            return 0
        else
            return 1
        fi
    fi
}

# Get version
getversion(){
    if [[ -s /etc/redhat-release ]]; then
        grep -oE  "[0-9.]+" /etc/redhat-release
    else
        grep -oE  "[0-9.]+" /etc/issue
    fi
}

# CentOS version
centosversion(){
    if check_sys sysRelease centos; then
        local code=$1
        local version="$(getversion)"
        local main_ver=${version%%.*}
        if [ "$main_ver" == "$code" ]; then
            return 0
        else
            return 1
        fi
    else
        return 1
    fi
}

# Get public IP address
get_ip(){
    local IP=$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )
    [ -z ${IP} ] && IP=$( wget -qO- -t1 -T2 ipv4.icanhazip.com )
    [ -z ${IP} ] && IP=$( wget -qO- -t1 -T2 ipinfo.io/ip )
    [ ! -z ${IP} ] && echo ${IP} || echo
}

# Pre-installation settings
pre_install(){
    if check_sys packageManager yum || check_sys packageManager apt; then
        # Not support CentOS 5
        if centosversion 5; then
            echo "Error: Not supported CentOS 5, please change to CentOS 6+/Debian 7+/Ubuntu 12+ and try again."
            exit 1
        fi
    else
        echo "Error: Your OS is not supported. please change OS to CentOS/Debian/Ubuntu and try again."
        exit 1
    fi
    get_char(){
        SAVEDSTTY=`stty -g`
        stty -echo
        stty cbreak
        dd if=/dev/tty bs=1 count=1 2> /dev/null
        stty -raw
        stty echo
        stty $SAVEDSTTY
    }
    echo
    echo "Press any key to start...or Press Ctrl+C to cancel"
    char=`get_char`
    # Install necessary dependencies
    if check_sys packageManager yum; then
        yum install -y unzip openssl-devel gcc swig python python-devel python-setuptools autoconf libtool libevent automake make curl curl-devel zlib-devel perl perl-devel cpio expat-devel gettext-devel
    elif check_sys packageManager apt; then
        apt-get -y update
        apt-get -y install python python-dev python-pip python-m2crypto curl wget unzip gcc swig automake make perl cpio build-essential
    fi
    cd ${cur_dir}
}

# Download files
download_files(){
    # Download libsodium file
    if ! wget --no-check-certificate -O libsodium-1.0.11.tar.gz https://github.com/jedisct1/libsodium/releases/download/1.0.11/libsodium-1.0.11.tar.gz; then
        echo "Failed to download libsodium-1.0.11.tar.gz!"
        exit 1
    fi
    # Download ShadowsocksR file
    if ! wget --no-check-certificate -O manyuser.zip https://github.com/breakwa11/shadowsocks/archive/manyuser.zip; then
        echo "Failed to download ShadowsocksR file!"
        exit 1
    fi
    # Download ShadowsocksR init script
    if check_sys packageManager yum; then
        if ! wget --no-check-certificate https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocksR -O /etc/init.d/shadowsocks; then
            echo "Failed to download ShadowsocksR chkconfig file!"
            exit 1
        fi
    elif check_sys packageManager apt; then
        if ! wget --no-check-certificate https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocksR-debian -O /etc/init.d/shadowsocks; then
            echo "Failed to download ShadowsocksR chkconfig file!"
            exit 1
        fi
    fi
}

# Config ShadowsocksR
config_shadowsocks(){
	read -p "请输入SSR连接密码（默认：123456aa）：" pwd
	[ -z "${pwd}" ] && pwd="123456aa"
	echo "密码为：${pwd}"
	echo ""

	echo "请输入SSR连接端口，如需开启多个端口请用空格隔开，（默认开启138）："
	read -a ports
	[ -z "${ports}" ] && ports="138"

cat>/etc/shadowsocks.json<<EOF
{
    "server":"0.0.0.0",
    "server_ipv6":"::",
    "local_address":"127.0.0.1",
    "local_port":1080,
    "timeout":120,
    "method":"chacha20",
    "protocol":"auth_sha1_v4_compatible",
    "protocol_param":"",
    "obfs":"http_simple_compatible",
    "obfs_param":"",
    "redirect":"",
    "dns_ipv6":false,
    "fast_open":true,
    "workers":1,
EOF

	port_password="    \"port_password\":{\n"

	for port in ${ports[@]}
	do
			port_password="${port_password}        \"${port}\":\"${pwd}\",\n"
	done

	port_password="${port_password%,*}\n    }\n}"
	echo -e "$port_password" >> /etc/shadowsocks.json
	echo "配置文件生成完毕！"

	echo ""
	for port in ${ports[@]}
	do
		echo -n "开放防火墙TCP ${port}..."
		firewall-cmd --zone=public --add-port=$port/tcp --permanent
		echo -n "开放防火墙UDP ${port}..."
		firewall-cmd --zone=public --add-port=$port/udp --permanent
	done
	echo -n "重启防火墙..."
	firewall-cmd --reload
	echo "防火墙已开放端口："
	firewall-cmd --list-ports
}

# Install ShadowsocksR
install(){
    # Install libsodium
    tar zxf libsodium-1.0.11.tar.gz
    cd libsodium-1.0.11
    ./configure && make && make install
    if [ $? -ne 0 ]; then
        echo "libsodium install failed!"
        install_cleanup
        exit 1
    fi
    echo "/usr/local/lib" > /etc/ld.so.conf.d/local.conf
    ldconfig
    # Install ShadowsocksR
    cd ${cur_dir}
    unzip -q manyuser.zip
    mv shadowsocks-manyuser/shadowsocks /usr/local/
    if [ -f /usr/local/shadowsocks/server.py ]; then
        chmod +x /etc/init.d/shadowsocks
        if check_sys packageManager yum; then
            chkconfig --add shadowsocks
            chkconfig shadowsocks on
        elif check_sys packageManager apt; then
            update-rc.d -f shadowsocks defaults
        fi
        /etc/init.d/shadowsocks start

        clear
        echo
        echo "配置完成, ShadowsocksR安装完毕!"
        echo -e "服务器IP: \033[41;37m $(get_ip) \033[0m"
        echo -e "服务器端口: \033[41;37m ${ports[@]} \033[0m"
        echo -e "密码: \033[41;37m ${pwd} \033[0m"
        echo -e "本地IP: \033[41;37m 127.0.0.1 \033[0m"
        echo -e "本地端口: \033[41;37m 1080 \033[0m"
        echo -e "协议方式: \033[41;37m auth_sha1_v4_compatible \033[0m"
        echo -e "混淆方式: \033[41;37m http_simple_compatible \033[0m"
        echo -e "加密方式: \033[41;37m chacha20 \033[0m"
        echo
        echo "Enjoy it!"
        echo
    else
        echo "ShadowsocksR install failed, please Email to Teddysun <i@teddysun.com> and contact"
        install_cleanup
        exit 1
    fi
}

# Install cleanup
install_cleanup(){
    cd ${cur_dir}
    rm -rf manyuser.zip shadowsocks-manyuser libsodium-1.0.11.tar.gz libsodium-1.0.11
}


# Uninstall ShadowsocksR
uninstall_shadowsocks(){
    printf "Are you sure uninstall ShadowsocksR? (y/n)"
    printf "\n"
    read -p "(Default: n):" answer
    [ -z ${answer} ] && answer="n"
    if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
        /etc/init.d/shadowsocks status > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            /etc/init.d/shadowsocks stop
        fi
        if check_sys packageManager yum; then
            chkconfig --del shadowsocks
        elif check_sys packageManager apt; then
            update-rc.d -f shadowsocks remove
        fi
        rm -f /etc/shadowsocks.json
        rm -f /etc/init.d/shadowsocks
        rm -f /var/log/shadowsocks.log
        rm -rf /usr/local/shadowsocks
        echo "ShadowsocksR uninstall success!"
    else
        echo
        echo "uninstall cancelled, nothing to do..."
        echo
    fi
}

# Install ShadowsocksR
install_shadowsocks(){
	config_shadowsocks
    rootness
    disable_selinux
    pre_install
    download_files
    install
    install_cleanup
}

# Initialization step
action=$1
[ -z $1 ] && action=install
case "$action" in
    install|uninstall)
    ${action}_shadowsocks
    ;;
    *)
    echo "Arguments error! [${action}]"
    echo "Usage: `basename $0` {install|uninstall}"
    ;;
esac
