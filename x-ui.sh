#!/bin/bash

红色='\033[0;31m'
绿色='\033[0;32m'
黄色='\033[0;33m'
普通='\033[0m'

# 添加一些基本功能
function 记录调试信息() {
    echo -e "${黄色}[调试] $* ${普通}"
}

function 记录错误信息() {
    echo -e "${红色}[错误] $* ${普通}"
}

function 记录信息() {
    echo -e "${绿色}[信息] $* ${普通}"
}

# 检查是否以root权限运行
[[ $EUID -ne 0 ]] && 记录错误信息 "错误：必须以root权限运行此脚本！ \n" && exit 1

# 检查操作系统并设置发行版本变量
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    发行版本=$ID
elif [[ -f /usr/lib/os-release ]]; then
    source /usr/lib/os-release
    发行版本=$ID
else
    echo "无法检查系统操作系统，请联系作者！" >&2
    exit 1
fi

echo "操作系统版本为: $发行版本"

操作系统版本=""
操作系统版本=$(grep -i version_id /etc/os-release | cut -d \" -f2 | cut -d . -f1)

if [[ "${发行版本}" == "centos" ]]; then
    if [[ ${操作系统版本} -lt 8 ]]; then
        echo -e "${红色} 请使用CentOS 8或更高版本 ${普通}\n" && exit 1
    fi
elif [[ "${发行版本}" == "ubuntu" ]]; then
    if [[ ${操作系统版本} -lt 20 ]]; then
        echo -e "${红色}请使用Ubuntu 20或更高版本！ ${普通}\n" && exit 1
    fi
elif [[ "${发行版本}" == "fedora" ]]; then
    if [[ ${操作系统版本} -lt 36 ]]; then
        echo -e "${红色}请使用Fedora 36或更高版本！ ${普通}\n" && exit 1
    fi
elif [[ "${发行版本}" == "debian" ]]; then
    if [[ ${操作系统版本} -lt 10 ]]; then
        echo -e "${红色} 请使用Debian 10或更高版本 ${普通}\n" && exit 1
    fi
elif [[ "${发行版本}" == "arch" ]]; then
    echo "操作系统为ArchLinux"
fi

# 声明变量
log_folder="${XUI_LOG_FOLDER:=/var/log}"
iplimit_log_path="${log_folder}/3xipl.log"
iplimit_banned_log_path="${log_folder}/3xipl-banned.log"

确认() {
    if [[ $# > 1 ]]; then
        echo && read -p "$1 [默认 $2]: " temp
        if [[ "${temp}" == "" ]]; then
            temp=$2
        fi
    else
        read -p "$1 [y/n]: " temp
    fi
    if [[ "${temp}" == "y" || "${temp}" == "Y" ]]; then
        return 0
    else
        return 1
    fi
}

确认重启() {
    确认 "重启面板，注意：重启面板也会重启xray" "y"
    if [[ $? == 0 ]]; then
        重启
    else
        显示菜单
    fi
}

在显示菜单之前() {
    echo && echo -n -e "${黄色}按回车键返回主菜单: ${普通}" && read temp
    显示菜单
}

安装() {
    bash <(curl -Ls https://raw.githubusercontent.com/MHSanaei/3x-ui/main/install.sh)
    if [[ $? == 0 ]]; then
        if [[ $# == 0 ]]; then
            启动
        else
            启动 0
        fi
    fi
}

更新() {
    确认 "此功能将强制重新安装最新版本，数据不会丢失。您是否要继续？" "n"
    if [[ $? != 0 ]]; then
        记录错误信息 "已取消"
        if [[ $# == 0 ]]; then
            在显示菜单之前
        fi
        return 0
    fi
    bash <(curl -Ls https://raw.githubusercontent.com/MHSanaei/3x-ui/main/install.sh)
    if [[ $? == 0 ]]; then
        记录信息 "更新完成，面板已自动重启"
        exit 0
    fi
}

卸载() {
    确认 "您确定要卸载面板吗？xray也会被卸载！" "n"
    if [[ $? != 0 ]]; then
        if [[ $# == 0 ]]; then
            show_menu
        fi
        return 0
    fi
    systemctl stop x-ui
    systemctl disable x-ui
    rm /etc/systemd/system/x-ui.service -f
    systemctl daemon-reload
    systemctl reset-failed
    rm /etc/x-ui/ -rf
    rm /usr/local/x-ui/ -rf

    echo ""
    echo -e "卸载成功，如果您想删除此脚本，请在退出脚本后运行 ${绿色}rm /usr/bin/x-ui -f${普通} 来删除它。"
    echo ""

    if [[ $# == 0 ]]; then
        在显示菜单之前
    fi
}

重置用户() {
    确认 "您确定要重置面板的用户名和密码吗？" "n"
    if [[ $? != 0 ]]; then
        if [[ $# == 0 ]]; then
            显示菜单
        fi
        return 0
    fi
    read -rp "请设置登录用户名 [默认为随机用户名]: " config_account
    [[ -z $config_account ]] && config_account=$(date +%s%N | md5sum | cut -c 1-8)
    read -rp "请设置登录密码 [默认为随机密码]: " config_password
    [[ -z $config_password ]] && config_password=$(date +%s%N | md5sum | cut -c 1-8)
    /usr/local/x-ui/x-ui setting -username ${config_account} -password ${config_password} >/dev/null 2>&1
    /usr/local/x-ui/x-ui setting -remove_secret >/dev/null 2>&1
    echo -e "面板登录用户名已重置为：${绿色} ${config_account} ${普通}"
    echo -e "面板登录密码已重置为：${绿色} ${config_password} ${普通}"
    echo -e "${黄色} 面板登录秘密令牌已禁用 ${普通}"
    echo -e "${绿色} 请使用新的登录用户名和密码访问X-UI面板。还记得它们！ ${普通}"
    确认重启
}

重置配置() {
    确认 "您确定要重置所有面板设置，帐户数据不会丢失，用户名和密码不会更改" "n"
    if [[ $? != 0 ]]; then
        if [[ $# == 0 ]]; then
            显示菜单
        fi
        return 0
    fi
    /usr/local/x-ui/x-ui setting -reset
    echo -e "所有面板设置已重置为默认值，请现在重新启动面板，并使用默认的 ${绿色}2053${普通} 端口访问web面板"
    确认重启
}

检查配置() {
    info=$(/usr/local/x-ui/x-ui setting -show true)
    if [[ $? != 0 ]]; then
        记录错误信息 "获取当前设置时出错，请检查日志"
        显示菜单
    fi
    记录信息 "${info}"
}

设置端口() {
    echo && echo -n -e "输入端口号[1-65535]: " && read port
    if [[ -z "${port}" ]]; then
        记录调试信息 "已取消"
        在显示菜单之前
    else
        /usr/local/x-ui/x-ui setting -port ${port}
        echo -e "端口已设置，请现在重新启动面板，并使用新端口 ${绿色}${port}${普通} 访问web面板"
        确认重启
    }
}

启动() {
    检查状态
    if [[ $? == 0 ]]; then
        echo ""
        记录信息 "面板正在运行，无需再次启动，如果需要重新启动，请选择重新启动"
    else
        systemctl start x-ui
        sleep 2
        检查状态
        if [[ $? == 0 ]]; then
            记录信息 "x-ui 启动成功"
        else
            记录错误信息 "面板启动失败，可能是因为启动时间超过两秒，请稍后检查日志信息"
        fi
    }

    if [[ $# == 0 ]]; then
        在显示菜单之前
    fi
}

停止() {
    检查状态
    if [[ $? == 1 ]]; then
        echo ""
        记录信息 "面板已停止，无需再次停止！"
    else
        systemctl stop x-ui
        sleep 2
        检查状态
        if [[ $? == 1 ]]; then
            记录信息 "x-ui 和 xray 成功停止"
        else
            记录错误信息 "面板停止失败，可能是因为停止时间超过两秒，请稍后检查日志信息"
        fi
    }

    if [[ $# == 0 ]]; then
        在显示菜单之前
    fi
}

重启() {
    systemctl restart x-ui
    sleep 2
    检查状态
    if [[ $? == 0 ]]; then
        记录信息 "x-ui 和 xray 重启成功"
    else
        记录错误信息 "面板重启失败，可能是因为启动时间超过两秒，请稍后检查日志信息"
    }
    if [[ $# == 0 ]]; then
        在显示菜单之前
    fi
}

状态() {
    systemctl status x-ui -l
    if [[ $# == 0 ]]; then
        在显示菜单之前
    fi
}

启用() {
    systemctl enable x-ui
    if [[ $? == 0 ]]; then
        记录信息 "x-ui 已成功设置为开机自启动"
    else
        记录错误信息 "x-ui 设置开机自启动失败"
    fi

    if [[ $# == 0 ]]; then
        在显示菜单之前
    fi
}

禁用() {
    systemctl disable x-ui
    if [[ $? == 0 ]]; then
        记录信息 "x-ui 自启动已成功取消"
    else
        记录错误信息 "x-ui 取消自启动失败"
    }

    if [[ $# == 0 ]]; then
        在显示菜单之前
    fi
}

显示日志() {
    journalctl -u x-ui.service -e --no-pager -f
    if [[ $# == 0 ]]; then
        在显示菜单之前
    fi
}
show_banlog() {
  if test -f "${iplimit_banned_log_path}"; then
    if [[ -s "${iplimit_banned_log_path}" ]]; then
      cat ${iplimit_banned_log_path}
    else
      echo -e "${red}日志文件为空。${plain}\n"  
    fi
  else
    echo -e "${red}未找到日志文件。请首先安装 Fail2ban 和 IP Limit。${plain}\n"
  }
}

enable_bbr() {
    if grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf && grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf; then
        echo -e "${green}BBR 已经启用！${plain}"
        exit 0
    fi

    # 检查操作系统并安装必要的软件包
    case "${release}" in
        ubuntu|debian)
            apt-get update && apt-get install -yqq --no-install-recommends ca-certificates
            ;;
        centos)
            yum -y update && yum -y install ca-certificates
            ;;
        fedora)
            dnf -y update && dnf -y install ca-certificates
            ;;
        *)
            echo -e "${red}不支持的操作系统。请检查脚本并手动安装必要的软件包。${plain}\n"
            exit 1
            ;;
    esac

    # 启用 BBR
    echo "net.core.default_qdisc=fq" | tee -a /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" | tee -a /etc/sysctl.conf

    # 应用更改
    sysctl -p

    # 验证 BBR 是否已启用
    if [[ $(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}') == "bbr" ]]; then
        echo -e "${green}成功启用 BBR。${plain}"
    else
        echo -e "${red}无法启用 BBR。请检查系统配置。${plain}"
    fi
}

update_shell() {
    wget -O /usr/bin/x-ui -N --no-check-certificate https://github.com/MHSanaei/3x-ui/raw/main/x-ui.sh
    if [[ $? != 0 ]]; then
        echo ""
        LOGE "无法下载脚本，请检查机器是否能够连接 Github"
        before_show_menu
    else
        chmod +x /usr/bin/x-ui
        LOGI "升级脚本成功，请重新运行脚本" && exit 0
    fi
}

# 0: 运行中, 1: 未运行, 2: 未安装
check_status() {
    if [[ ! -f /etc/systemd/system/x-ui.service ]]; then
        return 2
    fi
    temp=$(systemctl status x-ui | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
    if [[ "${temp}" == "运行中" ]]; then
        return 0
    else
        return 1
    fi
}

check_enabled() {
    temp=$(systemctl is-enabled x-ui)
    if [[ "${temp}" == "已启用" ]]; then
        return 0
    else
        return 1
    fi
}

check_uninstall() {
    check_status
    if [[ $? != 2 ]]; then
        echo ""
        LOGE "面板已安装，请不要重新安装"
        if [[ $# == 0 ]]; then
            before_show_menu
        fi
        return 1
    else
        return 0
    fi
}

check_install() {
    check_status
    if [[ $? == 2 ]]; then
        echo ""
        LOGE "请先安装面板"
        if [[ $# == 0 ]]; then
            before_show_menu
        fi
        return 1
    else
        return 0
    fi
}

show_status() {
    check_status
    case $? in
    0)
        echo -e "面板状态: ${green}运行中${plain}"
        show_enable_status
        ;;
    1)
        echo -e "面板状态: ${yellow}未运行${plain}"
        show_enable_status
        ;;
    2)
        echo -e "面板状态: ${red}未安装${plain}"
        ;;
    esac
    show_xray_status
}

show_enable_status() {
    check_enabled
    if [[ $? == 0 ]]; then
        echo -e "自动启动: ${green}是${plain}"
    else
        echo -e "自动启动: ${red}否${plain}"
    fi
}

check_xray_status() {
    count=$(ps -ef | grep "xray-linux" | grep -v "grep" | wc -l)
    if [[ count -ne 0 ]]; then
        return 0
    else
        return 1
    fi
}

show_xray_status() {
    check_xray_status
    if [[ $? == 0 ]]; then
        echo -e "xray 状态: ${green}运行中${plain}"
    else
        echo -e "xray 状态: ${red}未运行${plain}"
    fi
}

open_ports() {
    if ! command -v ufw &>/dev/null; then
        echo "ufw 防火墙未安装。正在安装..."
        apt-get update
        apt-get install -y ufw
    else
        echo "ufw 防火墙已经安装"
    fi

    # 检查防火墙是否处于非活动状态
    if ufw status | grep -q "状态: 活动"; then
        echo "防火墙已经处于活动状态"
    else
        # 打开必要的端口
        ufw allow ssh
        ufw allow http
        ufw allow https
        ufw allow 2053/tcp

        # 启用防火墙
        ufw --force enable
    fi

    # 提示用户输入要打开的端口列表
    read -p "输入要打开的端口（例如 80,443,2053 或范围 400-500）: " ports

    # 检查输入是否有效
    if ! [[ $ports =~ ^([0-9]+|[0-9]+-[0-9]+)(,([0-9]+|[0-9]+-[0-9]+))*$ ]]; then
        echo "错误：无效输入。请以逗号分隔的端口列表或端口范围（例如 80,443,2053 或 400-500）。" >&2
        exit 1
    fi

    # 使用 ufw 打开指定的端口
    IFS=',' read -ra PORT_LIST <<<"$ports"
    for port in "${PORT_LIST[@]}"; do
        if [[ $port == *-* ]]; then
            # 将范围分成起始端口和结束端口
            start_port=$(echo $port | cut -d'-' -f1)
            end_port=$(echo $port | cut -d'-' -f2)
            # 循环遍历范围并打开每个端口
            for ((i = start_port; i <= end_port; i++)); do
                ufw allow $i
            done
        else
            ufw allow "$port"
        fi
    done

    # 确认端口是否已打开
    ufw status | grep $ports
}

update_geo() {
    local defaultBinFolder="/usr/local/x-ui/bin"
    read -p "请输入 x-ui bin 文件夹路径。留空使用默认路径（默认: '${defaultBinFolder}'）" binFolder
    binFolder=${binFolder:-${defaultBinFolder}}
    if [[ ! -d ${binFolder} ]]; then
        LOGE "文件夹 ${binFolder} 不存在！"
        LOGI "创建 bin 文件夹: ${binFolder}..."
        mkdir -p ${binFolder}
    fi

    systemctl stop x-ui
    cd ${binFolder}
    rm -f geoip.dat geosite.dat geoip_IR.dat geosite_IR.dat
    wget -N https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat
    wget -N https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat
    wget -O geoip_IR.dat -N https://github.com/chocolate4u/Iran-v2ray-rules/releases/latest/download/geoip.dat
    wget -O geosite_IR.dat -N https://github.com/chocolate4u/Iran-v2ray-rules/releases/latest/download/geosite.dat
    systemctl start x-ui
    echo -e "${green}Geosite.dat + Geoip.dat + geoip_IR.dat + geosite_IR.dat 已成功更新到 bin 文件夹 '${binfolder}'！${plain}"
    before_show_menu
}

install_acme() {
    cd ~
    LOGI "安装 acme..."
    curl https://get.acme.sh | sh
    if [ $? -ne 0 ]; then
        LOGE "安装 acme 失败"
        return 1
    else
        LOGI "安装 acme 成功"
    fi
    return 0
}

ssl_cert_issue_main() {
    echo -e "${green}\t1.${plain} 获取 SSL 证书"
    echo -e "${green}\t2.${plain} 吊销 SSL 证书"
    echo -e "${green}\t3.${plain} 强制更新 SSL 证书"
    echo -e "${green}\t0.${plain} 返回主菜单"
    read -p "选择一个选项: " choice
    case "$choice" in
        0)
            show_menu ;;
        1) 
            ssl_cert_issue ;;
        2) 
            local domain=""
            read -p "请输入要吊销证书的域名: " domain
            ~/.acme.sh/acme.sh --revoke -d ${domain}
            LOGI "证书已吊销"
            ;;
        3)
            local domain=""
            read -p "请输入要强制更新 SSL 证书的域名: " domain
            ~/.acme.sh/acme.sh --renew -d ${domain} --force ;;
        *) echo "无效的选项" ;;
    esac
}

ssl_cert_issue() {
    # 首先检查是否已安装 acme.sh
    if ! command -v ~/.acme.sh/acme.sh &>/dev/null; then
        echo "未找到 acme.sh。我们将安装它"
        install_acme
        if [ $? -ne 0 ]; then
            LOGE "安装 acme 失败，请查看日志"
            exit 1
        fi
    fi
    # 其次安装 socat
    case "${release}" in
        ubuntu|debian)
            apt update && apt install socat -y ;;
        centos)
            yum -y update && yum -y install socat ;;
        fedora)
            dnf -y update && dnf -y install socat ;;
        *)
            echo -e "${red}不支持的操作系统。请检查脚本并手动安装必要的软件包。${plain}\n"
            exit 1 ;;
    esac
    if [ $? -ne 0 ]; then
        LOGE "安装 socat 失败，请查看日志"
        exit 1
    else
        LOGI "安装 socat 成功..."
    fi

    # 获取域名，并验证
    local domain=""
    read -p "请输入您的域名：" domain
    LOGD "您的域名是：${domain}，正在检查..."
    # 这里需要判断是否已存在证书
    local currentCert=$(~/.acme.sh/acme.sh --list | tail -1 | awk '{print $1}')

    if [ ${currentCert} == ${domain} ]; then
        local certInfo=$(~/.acme.sh/acme.sh --list)
        LOGE "系统已经存在证书，无法再次申请，当前证书详情如下："
        LOGI "$certInfo"
        exit 1
    else
        LOGI "您的域名已准备好申请证书..."
    fi
}
# 创建用于安装证书的目录
certPath="/root/cert/${domain}"
if [ ! -d "$certPath" ]; then
    mkdir -p "$certPath"
else
    rm -rf "$certPath"
    mkdir -p "$certPath"
fi

# 在这里获取所需的端口
local WebPort=80
WebPort=80
LOGI "将使用端口:${WebPort} 发放证书，请确保此端口已打开..."

# 注意：这应该由用户处理
# 打开端口并杀死占用的进程
~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
~/.acme.sh/acme.sh --issue -d ${domain} --standalone --httpport ${WebPort}
if [ $? -ne 0 ]; then
    LOGE "证书发放失败，请检查日志"
    rm -rf ~/.acme.sh/${domain}
    exit 1
else
    LOGE "证书发放成功，正在安装证书..."
fi

# 安装证书
~/.acme.sh/acme.sh --installcert -d ${domain} \
    --key-file /root/cert/${domain}/privkey.pem \
    --fullchain-file /root/cert/${domain}/fullchain.pem

if [ $? -ne 0 ]; then
    LOGE "证书安装失败，退出"
    rm -rf ~/.acme.sh/${domain}
    exit 1
else
    LOGI "证书安装成功，启用自动更新..."
fi

~/.acme.sh/acme.sh --upgrade --auto-upgrade
if [ $? -ne 0 ]; then
    LOGE "自动更新失败，证书详情："
    ls -lah cert/*
    chmod 755 $certPath/*
    exit 1
else
    LOGI "自动更新成功，证书详情："
    ls -lah cert/*
    chmod 755 $certPath/*
fi

ssl_cert_issue_CF() {
    local domain=""
    read -p "请输入要吊销证书的域名: " domain
    ~/.acme.sh/acme.sh --revoke -d ${domain}
    LOGI "证书已吊销"
}

ssl_cert_issue() {
    local domain=""
    read -p "请输入要强制续订 SSL 证书的域名: " domain
    ~/.acme.sh/acme.sh --renew -d ${domain} --force
}

warp_cloudflare() {
    bash <(curl -sSL https://raw.githubusercontent.com/hamid-gh98/x-ui-scripts/main/install_warp_proxy.sh)
}

run_speedtest() {
    local pkg_manager=""
    local speedtest_install_script=""

    if command -v dnf &> /dev/null; then
        pkg_manager="dnf"
        speedtest_install_script="https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.rpm.sh"
    elif command -v yum &> /dev/null; then
        pkg_manager="yum"
        speedtest_install_script="https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.rpm.sh"
    elif command -v apt-get &> /dev/null; then
        pkg_manager="apt-get"
        speedtest_install_script="https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh"
    elif command -v apt &> /dev/null; then
        pkg_manager="apt"
        speedtest_install_script="https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh"
    fi

    if [[ -z $pkg_manager ]]; then
        echo "错误：找不到包管理器。您可能需要手动安装 Speedtest。"
        return 1
    else
        curl -s $speedtest_install_script | bash
        $pkg_manager install -y speedtest
    fi

    speedtest
}

create_iplimit_jails() {
    local bantime="${1:-5}"

    cat << EOF > /etc/fail2ban/jail.d/3x-ipl.conf
[3x-ipl]
enabled=true
filter=3x-ipl
action=3x-ipl
logpath=${iplimit_log_path}
maxretry=4
findtime=60
bantime=${bantime}m
EOF

    cat << EOF > /etc/fail2ban/filter.d/3x-ipl.conf
[Definition]
datepattern = ^%%Y/%%m/%%d %%H:%%M:%%S
failregex   = \[LIMIT_IP\]\s*Email\s*=\s*<F-USER>.+</F-USER>\s*\|\|\s*SRC\s*=\s*<ADDR>
ignoreregex =
EOF

    cat << EOF > /etc/fail2ban/action.d/3x-ipl.conf
[INCLUDES]
before = iptables-common.conf

[Definition]
actionstart = <iptables> -N f2b-<name>
              <iptables> -A f2b-<name> -j <returntype>
              <iptables> -I <chain> -p <protocol> -j f2b-<name>

actionstop = <iptables> -D <chain> -p <protocol> -j f2b-<name>
             <actionflush>
             <iptables> -X f2b-<name>

actioncheck = <iptables> -n -L <chain> | grep -q 'f2b-<name>[ \t]'

actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>
            echo "\$(date +"%%Y/%%m/%%d %%H:%%M:%%S")   封禁   [Email] = <F-USER> [IP] = <ip> 封禁 <bantime> 秒。" >> ${iplimit_banned_log_path}

actionunban = <iptables> -D f2b-<name> -s <ip> -j <blocktype>
              echo "\$(date +"%%Y/%%m/%%d %%H:%%M:%%S")   解封   [Email] = <F-USER> [IP] = <ip> 已解封。" >> ${iplimit_banned_log_path}

[Init]
EOF

    echo -e "${green}创建了 IP 限制监狱文件，封禁时间为 ${bantime} 分钟。${plain}"
}

iplimit_remove_conflicts() {
    local jail_files=(
        /etc/fail2ban/jail.conf
        /etc/fail2ban/jail.local
    )

    for file in "${jail_files[@]}"; do
        if test -f "${file}" && grep -qw '3x-ipl' ${file}; then
            sed -i "/\[3x-ipl\]/,/^$/d" ${file}
            echo -e "${yellow}正在删除监狱文件 (${file}) 中的 [3x-ipl] 冲突！${plain}\n"
        fi
    done
}

iplimit_main() {
    echo -e "${green}\t1.${plain} 安装 Fail2ban 并配置 IP 限制"
    echo -e "${green}\t2.${plain} 更改封禁时长"
    echo -e "${green}\t3.${plain} 解封所有用户"
    echo -e "${green}\t4.${plain} 检查日志"
    echo -e "${green}\t5.${plain} Fail2ban 状态"
    echo -e "${green}\t6.${plain} 卸载 IP 限制"
    echo -e "${green}\t0.${plain} 返回主菜单"
    read -p "选择一个选项: " choice
    case "$choice" in
        0)
            show_menu ;;
        1)
            install_iplimit ;;
        2)
            read -rp "请输入新的封禁时长，单位为分钟 [默认 5 分钟]: " NUM
            if [[ $NUM =~ ^[0-9]+$ ]]; then
                create_iplimit_jails ${NUM}
                systemctl restart fail2ban
            else
                echo -e "${red}${NUM} 不是一个有效的数字！请重试。${plain}"
            fi
            iplimit_main ;;
        3)
            fail2ban-client reload --restart --unban 3x-ipl
            echo -e "${green}所有用户已解封。${plain}"
            iplimit_main
            ;;
        4)
            show_banlog
            ;;
        5)
            service fail2ban status
            ;;
        6)
            remove_iplimit ;;
        *) echo "无效的选择" ;;
    esac
}
install_iplimit() {
    if ! command -v fail2ban-client &>/dev/null; then
        echo -e "${green}Fail2ban未安装。正在安装...！${plain}\n"
        # 检查操作系统并安装必要的软件包
        case "${release}" in
            ubuntu|debian)
                apt update && apt install fail2ban -y ;;
            centos)
                yum -y update && yum -y install fail2ban ;;
            fedora)
                dnf -y update && dnf -y install fail2ban ;;
            *)
                echo -e "${red}不支持的操作系统。请检查脚本并手动安装必要的软件包。${plain}\n"
                exit 1 ;;
        esac
        echo -e "${green}成功安装Fail2ban！${plain}\n"
    else
        echo -e "${yellow}Fail2ban已经安装。${plain}\n"
    fi

    echo -e "${green}配置IP限制...${plain}\n"

    # 确保没有冲突的监狱文件
    iplimit_remove_conflicts

    # 检查日志文件是否存在
    if ! test -f "${iplimit_banned_log_path}"; then
        touch ${iplimit_banned_log_path}
    fi

    # 检查服务日志文件是否存在，以防Fail2ban返回错误
    if ! test -f "${iplimit_log_path}"; then
        touch ${iplimit_log_path}
    fi

    # 创建IP限制监狱文件
    # 我们没有在此处传递bantime，以使用默认值
    create_iplimit_jails

    # 启动Fail2ban
    if ! systemctl is-active --quiet fail2ban; then
        systemctl start fail2ban
    else
        systemctl restart fail2ban
    fi
    systemctl enable fail2ban

    echo -e "${green}成功安装和配置IP限制！${plain}\n"
    before_show_menu
}

remove_iplimit(){
    echo -e "${green}\t1.${plain} 仅删除IP限制配置"
    echo -e "${green}\t2.${plain} 卸载Fail2ban和IP限制"
    echo -e "${green}\t0.${plain} 中止"
    read -p "选择一个选项: " num
    case "$num" in
        1) 
            rm -f /etc/fail2ban/filter.d/3x-ipl.conf
            rm -f /etc/fail2ban/action.d/3x-ipl.conf
            rm -f /etc/fail2ban/jail.d/3x-ipl.conf
            systemctl restart fail2ban
            echo -e "${green}成功删除IP限制！${plain}\n"
            before_show_menu ;;
        2)  
            rm -rf /etc/fail2ban
            systemctl stop fail2ban
            case "${release}" in
                ubuntu|debian)
                    apt-get purge fail2ban -y;;
                centos)
                    yum remove fail2ban -y;;
                fedora)
                    dnf remove fail2ban -y;;
                *)
                    echo -e "${red}不支持的操作系统。请手动卸载Fail2ban。${plain}\n"
                    exit 1 ;;
            esac
            echo -e "${green}成功卸载Fail2ban和IP限制！${plain}\n"
            before_show_menu ;;
        0) 
            echo -e "${yellow}已取消。${plain}\n"
            iplimit_main ;;
        *) 
            echo -e "${red}无效选项。请选择有效的数字。${plain}\n"
            remove_iplimit ;;
    esac
}

show_usage() {
    echo "x-ui控制菜单用法: "
    echo "------------------------------------------"
    echo -e "x-ui              - 进入控制菜单"
    echo -e "x-ui start        - 启动x-ui"
    echo -e "x-ui stop         - 停止x-ui"
    echo -e "x-ui restart      - 重启x-ui"
    echo -e "x-ui status       - 显示x-ui状态"
    echo -e "x-ui enable       - 启用系统启动时的x-ui"
    echo -e "x-ui disable      - 禁用系统启动时的x-ui"
    echo -e "x-ui log          - 检查x-ui日志"
    echo -e "x-ui banlog       - 检查Fail2ban封禁日志"
    echo -e "x-ui update       - 更新x-ui"
    echo -e "x-ui install      - 安装x-ui"
    echo -e "x-ui uninstall    - 卸载x-ui"
    echo "------------------------------------------"
}

show_menu() {
    echo -e "
  ${green}3X-ui面板管理脚本${plain}
  ${green}0.${plain} 退出脚本
————————————————
  ${green}1.${plain} 安装x-ui
  ${green}2.${plain} 更新x-ui
  ${green}3.${plain} 卸载x-ui
————————————————
  ${green}4.${plain} 重置用户名、密码和密钥令牌
  ${green}5.${plain} 重置面板设置
  ${green}6.${plain} 更改面板端口
  ${green}7.${plain} 查看当前面板设置
————————————————
  ${green}8.${plain} 启动x-ui
  ${green}9.${plain} 停止x-ui
  ${green}10.${plain} 重启x-ui
  ${green}11.${plain} 检查x-ui状态
  ${green}12.${plain} 检查x-ui日志
————————————————
  ${green}13.${plain} 启用系统启动时的x-ui
  ${green}14.${plain} 禁用系统启动时的x-ui
————————————————
  ${green}15.${plain} SSL证书管理
  ${green}16.${plain} Cloudflare SSL证书
  ${green}17.${plain} IP限制管理
  ${green}18.${plain} WARP管理
————————————————
  ${green}19.${plain} 启用BBR
  ${green}20.${plain} 更新Geo文件
  ${green}21.${plain} 激活防火墙和打开端口
  ${green}22.${plain} Ookla的速度测试
"
    show_status
    echo && read -p "请输入您的选择 [0-22]: " num

    case "${num}" in
    0)
        exit 0
        ;;
    1)
        check_uninstall && install
        ;;
    2)
        check_install && update
        ;;
    3)
        check_install && uninstall
        ;;
    4)
        check_install && reset_user
        ;;
    5)
        check_install && reset_config
        ;;
    6)
        check_install && set_port
        ;;
    7)
        check_install && check_config
        ;;
    8)
        check_install && start
        ;;
    9)
        check_install && stop
        ;;
    10)
        check_install && restart
        ;;
    11)
        check_install && status
        ;;
    12)
        check_install && show_log
        ;;
    13)
        check_install && enable
        ;;
    14)
        check_install && disable
        ;;
    15)
        ssl_cert_issue_main
        ;;
    16)
        ssl_cert_issue_CF
        ;;
    17)
        iplimit_main
        ;;
    18)
        warp_cloudflare
        ;;
    19)
        enable_bbr
        ;;
    20)
        update_geo
        ;;
    21)
        open_ports
        ;;
    22)
        run_speedtest
        ;;    
    *)
        LOGE "请输入正确的数字[0-22]"
        ;;
    esac
}

if [[ $# > 0 ]]; then
    case $1 in
    "start")
        check_install 0 && start 0
        ;;
    "stop")
        check_install 0 && stop 0
        ;;
    "restart")
        check_install 0 && restart 0
        ;;
    "status")
        check_install 0 && status 0
        ;;
    "enable")
        check_install 0 && enable 0
        ;;
    "disable")
        check_install 0 && disable 0
        ;;
    "log")
        check_install 0 && show_log 0
        ;;
    "banlog")
        check_install 0 && show_banlog 0
        ;;
    "update")
        check_install 0 && update 0
        ;;
    "install")
        check_uninstall 0 && install 0
        ;;
    "uninstall")
        check_install 0 && uninstall 0
        ;;
    *) show_usage ;;
    esac
else
    show_menu
fi
