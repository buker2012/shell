clear
echo
echo "##########################################"
echo "# 一键配置ShadowsocksR for CentOS 7      #"
echo "# Web: http://branit.cc                  #"
echo "# Author: Buker                          #"
echo "##########################################"
echo

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
echo "重启SSR"
/etc/init.d/shadowsocks restart
echo "配置完成！"

