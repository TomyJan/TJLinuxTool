#!/usr/bin/env bash

# 必须 root 运行
if [ "$(id -u)" -ne 0 ]; then
    echo "请用 root 权限运行此脚本"
    exit 1
fi

# 颜色支持判断
if [ -t 1 ] && command -v tput >/dev/null 2>&1; then
    RED=$(tput setaf 1)
    GREEN=$(tput setaf 2)
    RESET=$(tput sgr0)
    SUPPORT_SELECT=true
else
    RED=""
    GREEN=""
    RESET=""
    SUPPORT_SELECT=false
fi

# 参数解析
MODE="menu"
PUBKEY=""
USERNAME=""

while getopts "m:p:u:" opt; do
    case $opt in
        m) MODE="$OPTARG" ;;
        p) PUBKEY="$OPTARG" ;;
        u) USERNAME="$OPTARG" ;;
        *) echo "用法: $0 [-m menu|sequential] [-p 公钥] [-u 用户名]"; exit 1 ;;
    esac
done

# 粗略校验公钥格式
if [ -n "$PUBKEY" ] && ! [[ $PUBKEY =~ ^ssh-ed25519\ [A-Za-z0-9+/=]{68,}\ [a-zA-Z0-9@._-]+$ ]]; then
    echo "${RED}公钥格式不对，应类似：ssh-ed25519 AAAA... comment${RESET}"
    exit 1
fi

# ────────────────────────────────────────────────
# 统一密钥管理（扁平列表）
# ────────────────────────────────────────────────
manage_keys() {
    echo "========================================"
    echo "  管理系统所有用户的 SSH 密钥与公钥"
    echo "========================================"
    echo "正在扫描所有用户 .ssh 目录..."

    declare -a items=()
    declare -a descs=()
    declare -a targets=()  # 格式: 类型|目标1|目标2|用户

    idx=0
    while IFS=: read -r user _ _ _ _ home _; do
        [ -z "$home" ] || [ ! -d "$home/.ssh" ] && continue
        auth="$home/.ssh/authorized_keys"

        # 私钥对
        for priv in "$home/.ssh"/id_*; do
            [ ! -f "$priv" ] || [[ $priv == *.pub ]] && continue
            pub="${priv}.pub"
            if [ -f "$pub" ]; then
                fp=$(ssh-keygen -l -f "$pub" 2>/dev/null | cut -d' ' -f2,3 || echo "指纹不可读")
                desc="$user 私钥对: $(basename "$priv")  → $fp"
            else
                desc="$user 私钥: $(basename "$priv") （无 .pub）"
            fi
            ((idx++))
            items+=("$idx")
            descs+=("$desc")
            targets+=("priv|$priv|$user")
        done

        # authorized_keys 每行公钥
        if [ -s "$auth" ]; then
            ln=0
            while IFS= read -r line; do
                ((ln++))
                [[ -z "$line" || $line =~ ^# ]] && continue
                type=$(echo "$line" | awk '{print $1}')
                key=$(echo "$line" | awk '{print $2}')
                comment=$(echo "$line" | cut -d' ' -f3-)
                short=${key:0:20}...
                desc="$user 登录公钥: $type $short $comment  (第${ln}行)"
                ((idx++))
                items+=("$idx")
                descs+=("$desc")
                targets+=("auth|$auth|$ln|$user")
            done < "$auth"
        fi
    done < /etc/passwd

    if [ ${#descs[@]} -eq 0 ]; then
        echo "  系统中没有任何 SSH 密钥或公钥"
        echo "========================================"
        return
    fi

    echo "  找到以下条目："
    echo "----------------------------------------"
    for i in "${!descs[@]}"; do
        printf " %3d. %s\n" "${items[i]}" "${descs[i]}"
    done
    echo "----------------------------------------"

    # 选择
    selected=-1
    if $SUPPORT_SELECT; then
        PS3="要删除哪一项？(0=退出) "
        select _ in "${descs[@]}"; do
            selected=$((REPLY-1))
            [[ $REPLY == 0 ]] && selected=-1
            break
        done
    else
        read -p "输入序号删除 (0=退出): " num
        [[ $num == 0 || -z $num ]] && return
        selected=$((num-1))
    fi

    (( selected < 0 || selected >= ${#targets[@]} )) && { echo "无效选择"; return; }

    IFS='|' read -r typ p1 p2 p3 <<< "${targets[selected]}"

    case $typ in
        priv)
            rm -f "$p1" "${p1}.pub" 2>/dev/null
            echo "${GREEN}已删除 $p3 的私钥对 $(basename "$p1")${RESET}"
            ;;
        auth)
            sed -i "${p2}d" "$p1"
            echo "${GREEN}已删除 $p3 的 authorized_keys 第 ${p2} 行${RESET}"
            ;;
    esac
}

# ────────────────────────────────────────────────
# 创建用户 + 密码 + 密钥
# ────────────────────────────────────────────────
create_user() {
    echo "========================================"
    echo "          创建新用户并配置密钥"
    echo "========================================"

    local user="$USERNAME"
    [ -z "$user" ] && read -p "新用户名: " user
    [ -z "$user" ] && { echo "用户名不能为空"; return 1; }

    if id "$user" &>/dev/null; then
        echo "${RED}用户 $user 已存在${RESET}"
        return 1
    fi

    useradd -m -s /bin/bash "$user" || { echo "创建用户失败"; return 1; }
    echo "用户 $user 创建成功"

    read -s -p "为 $user 设置密码: " pass; echo
    [ -z "$pass" ] && { echo "密码不能为空"; userdel -r "$user"; return 1; }
    echo "$user:$pass" | chpasswd

    # 创建 .ssh 并写入密钥
    mkdir -p "/home/$user/.ssh"
    chmod 700 "/home/$user/.ssh"

    local key="$PUBKEY"
    [ -z "$key" ] && read -p "粘贴公钥 (ssh-ed25519 ...): " key
    [ -z "$key" ] && { echo "公钥不能为空"; userdel -r "$user"; return 1; }

    echo "$key" > "/home/$user/.ssh/authorized_keys"
    chmod 600 "/home/$user/.ssh/authorized_keys"
    chown -R "$user:$user" "/home/$user/.ssh"

    # ─────────────── 解决常见警告 ───────────────
    # 1. 解决 ulimit 警告：只设置 soft limit（普通用户能改的）
    # 常见值 4096 或 65535，根据需求选一个
    echo "ulimit -Sn 65535" >> "/home/$user/.bashrc"
    # 或者更安全：只在 interactive shell 生效
    echo "[ -t 0 ] && ulimit -Sn 65535 2>/dev/null || true" >> "/home/$user/.bashrc"
    chown "$user:$user" "/home/$user/.bashrc"

    # 2. 创建空的 .Xauthority 避免 xauth 警告
    touch "/home/$user/.Xauthority"
    chown "$user:$user" "/home/$user/.Xauthority"
    chmod 600 "/home/$user/.Xauthority"

    # ─────────────── 允许 sudo ───────────────
    # 最简单方式：加到 sudo 组（大多数发行版都支持）
    usermod -aG sudo "$user" 2>/dev/null || usermod -aG wheel "$user" 2>/dev/null

    # 或者更保险：直接创建 /etc/sudoers.d/ 文件
    echo "$user ALL=(ALL:ALL) NOPASSWD:ALL" > "/etc/sudoers.d/$user"
    chmod 0440 "/etc/sudoers.d/$user"

    echo "密钥已写入 authorized_keys"
    ls -l "/home/$user/.ssh/authorized_keys"

    read -p "测试一下能用密钥登录吗？确认后继续 (y/n): " ok
    [[ $ok != [yY]* ]] && { echo "已取消后续操作"; return 1; }

    echo "${GREEN}用户 $user 配置完成（已允许 sudo，无常见警告）${RESET}"
    return 0
}

# ────────────────────────────────────────────────
# 检查 & 修改 sshd_config
# ────────────────────────────────────────────────
config_ssh() {
    echo "========================================"
    echo "     检查并修正 SSH 服务配置"
    echo "========================================"

    local conf="/etc/ssh/sshd_config"
    [ ! -f "$conf" ] && { echo "sshd_config 不存在"; return 1; }

    cp -p "$conf" "${conf}.$(date +%Y%m%d-%H%M%S).bak"

    echo "当前关键配置："
    grep -E '^(#)?PubkeyAuthentication|^(#)?PermitRootLogin|^(#)?PasswordAuthentication' "$conf" || true

    sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/'     "$conf"
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/'               "$conf"
    sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' "$conf"

    echo -e "\n修改后："
    grep -E 'PubkeyAuthentication|PermitRootLogin|PasswordAuthentication' "$conf"

    read -p "确认以上配置正确并要重启 sshd？(y/n) " go
    if [[ $go == [yY]* ]]; then
        systemctl restart sshd
        if systemctl is-active --quiet sshd; then
            echo "${GREEN}sshd 重启成功${RESET}"
        else
            echo "${RED}sshd 重启失败！请检查 journalctl -u sshd${RESET}"
        fi
    else
        echo "已取消，已保留备份"
    fi
}

# ────────────────────────────────────────────────
# 主程序
# ────────────────────────────────────────────────
if [ "$MODE" = "sequential" ]; then
    manage_keys
    if create_user; then
        config_ssh
    else
        echo "创建用户未完成，跳过 ssh 配置修改"
    fi
else
    while true; do
        echo "========================================"
        echo "              主 菜 单"
        echo "========================================"
        echo "  1) 管理所有用户的密钥 / 公钥"
        echo "  2) 创建新用户并配置密钥登录"
        echo "  3) 检查并修正 sshd 配置"
        echo "  0) 退出"
        echo "========================================"

        if $SUPPORT_SELECT; then
            PS3="请选择: "
            select opt in "管理密钥" "创建用户" "配置SSH" "退出"; do
                case $REPLY in
                    1) manage_keys ;;
                    2) create_user ;;
                    3) config_ssh ;;
                    4) exit 0 ;;
                    *) echo "无效选项" ;;
                esac
                break
            done
        else
            read -p "输入数字: " ch
            case $ch in
                1) manage_keys ;;
                2) create_user ;;
                3) config_ssh ;;
                0) exit 0 ;;
                *) echo "请输入 0-3" ;;
            esac
        fi
    done
fi
