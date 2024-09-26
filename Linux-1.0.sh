#!/bin/bash

# -----------------------------------------------------------
# 文件名:			centos8.sh
# 描述: 		安全基线检查-linux
# 使用:			chmod 711 linux.sh
# 作者：         标准化室-z@gmail.com 
# 开发版本：v0.9.8    2023.7.28
# 更新说明：a）增加MariaDB数据库的SSL登录模式
#           b）修改SSH登录的方式，使用sshpass+ssh的形式 ！！！！需要提前安装sshpass（可以在线安装）
#           c）自动获取脚本名:file_name=`basename $0`   echo $file_name
#			d）无需提前安装sshpass，未安装可在线安装
#			e）ssh登录可完整实现，在远程服务器上执行本地脚本文件
#			f）实现重定向到/var/exam/exam.txt
#			g）提供命令实例，实现快速测评，无任何学习该脚本的成本，如选择1，实现centos8的基线测评
#			h）提供重定向文件的时间戳，方便查看
#			i）添加ubuntu20.04，补充未具体说明的代码，修改错误的代码
#
# 计划：    a）
#           b）
#           c）后续加入suse等其他版本的操作系统，计划是一个脚本文件可以解决大多主流操作系统
#           d）
# 版权归属：©
# -----------------------------------------------------------



echo -e "\033[34m
    _                     _                   
   | |      __   __      | |    
   | |     / /   \ \     | |   
   |_| ___/ /     \ \___ |_|  
    __/____/       \____\__      
   |  /     _________   \  |     
   | \     |  _______|   / |  	            _                                            _ 
    \ \    | |_______   / /       ___ _   _| |__   ___ _ __ ___  ___  ___       __ _  __| |
     \ \   |_______  | / /       / __| | | | '_ \ / _ \ '__/ __|/ _ \/ __|____ / _\` |/ _\` |
      \ \   _      | |/ /       | (__| |_| | |_) |  __/ |  \__ \  __/ (_|_____| (_| | (_| |
       \ \ | |     | / /         \___|\__, |_.__/ \___|_|  |___/\___|\___|     \__, |\__,_| 
        \ \| |_____|/ /               |___/                                    |___/       
         \ \ _____ / / 
          \ \     / /
           \ \   / /
            \ \ / /
              \V/                                                                     V0.9.8
\033[0m"


echo -e ">############################################################################################<"
echo -e "\033[33m# --help  -h                                                     ##查看帮助 \033[0m\r"
echo -e "\033[33m# -os {[option] [value]}                                         ##选择操作系统版本\033[0m\r"
echo -e "\033[33m# --database -db {[option] [value]}                              ##选择数据库厂商以及版本号	 \033[0m\r"
echo -e "\033[33m# -ssh                                                           ##进行ssh远程登录目标服务器 \033[0m\r"
echo -e "\033[33m# -sample -s                                                     ##查看目前支持实例化的测评对象 \033[0m\r"
echo -e ">############################################################################################<"
echo
echo



###################################################### 操作系统-CentOS8 ############################################################
centos8(){
IFS=""

# ************************************ 重定向到输出文件 ************************************
# 重定向的说明，询问是否使用重定向到指定目录文件
read -p "请问是否需要将测评结果输出到/var/exam/{os}.txt？[yes/no]" redirects
if [[ $redirects = "yes" ]] ||  [[ $redirects = "y" ]];then
	mkdir -p /var/exam/
	touch /var/exam/centos8_$(date +%Y-%m-%d\ %H:%M:%S).txt
	redirects_catalogs="/var/exam/centos8_$(date +%Y-%m-%d\ %H:%M:%S).txt"
	exec >"$redirects_catalogs"
fi

echo "# ---------------------------------------------------------------------"
echo -e "# 简介: \t 检查Linux-CentOS8-安全计算环境-4级" 
echo -e "# 系统时间:\t "`date +'%Y-%m-%d %H:%S'`
echo -e "# 系统版本:\t "`cat /etc/redhat-release`
echo -e "# 内核版本:\t "`uname -a`
echo "# ---------------------------------------------------------------------"
echo



# 系统IP地址
echo -e "\033[32m>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> [IP地址:] <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\033[0m"
echo -e "主机名: \t\t" `hostname -s`
echo -e "IP地址: \t\t " `ifconfig | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -v 127 | awk '{print $2}'` 
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
echo


# ************************************ 身份鉴别a） ************************************
echo "************************************ 身份鉴别 ************************************"
echo
echo
echo "------------------------------- 身份鉴别措施 -------------------------------"
# 是否具备身份鉴别措施
echo -e "\033[33m>>>>>>>>>>>>>>>>>>>> [是否存在自动登录鉴别措施:] <<<<<<<<<<<<<<<<<<<<\033[0m"

Authentication=`grep 'AutomaticLoginEnable\|AutomaticLogin' /etc/gdm/custom.conf`
if [[ -n $Authentication ]]; then
	echo $Authentication
else
	echo -e "\033[31m没有设置自动登录的账户\033[0m"
fi
echo
echo

#是否存在rsh服务
echo -e "\033[33m>>>>>>>>>>>>>>>>>>>> [是否存在rsh-server远程登录管理服务:] <<<<<<<<<<<<<<<<<<<<\033[0m"
rsh=`rpm -qa|grep -i 'rsh'`
if [[ -n $rsh ]]; then
	echo -e "\033[32m安装了rsh远程管理服务:\n\033[0m"$rsh
else
	echo -e "\033[31m未安装rsh远程登录管理服务\033[0m"
fi
echo

# 是否配置了rsh服务
echo -e "\033[33m>>>>>>>>>>>>>>>>>>>> [是否配置rsh-server远程登录管理服务:] <<<<<<<<<<<<<<<<<<<<\033[0m"
rhosts=`find /root -name .rhosts -print -exec cat {} \;`
equiv=`find /etc -name hosts.equiv -print -exec cat {} \;`
if [[ -n $rhosts ]]; then
	echo $rhosts
else
	echo $equiv
fi
echo

echo -e "\033[33m>>>>>>>>>>>>>>>>>>>> [/etc/pam.d/sshd是否存在pam.listfile.so认证模块:] <<<<<<<<<<<<<<<<<<<<\033[0m"
listfile=`grep 'pam.listfile.so' /etc/pam.d/sshd`
if [[ -n $listfile ]]; then
	echo -e "\033[32m配置了pam.listfile.so认证模块:\n\033[0m" $listfile
else
	echo -e "\033[31m未配置pam.listfile.so认证模块\033[0m"
fi
echo
echo
echo
echo

echo "------------------------------- 身份标识唯一性 -------------------------------"
echo ">>>>>>>>>>>>>>>>>>>> [身份标识唯一性是否仅存在root账户UID=0:] <<<<<<<<<<<<<<<<<<<<"
#是否仅存在root账户的UID=0
uid=`awk -F: '($3==0)' /etc/passwd |grep -v 'root'`
if [[ -n $uid ]];then
	echo -e "存在除root账户外UID为0的账户:\n"$uid
else
	echo "仅存在root账户的UID为0"
fi
echo

# 是否有空口令 
echo "------------------------------- 空口令 -------------------------------"
echo ">>>>>>>>>>>>>>>>>>>> [是否存在空口令账户:] <<<<<<<<<<<<<<<<<<<<"
empty_passwd=`awk -F: 'length($2)==0 {print $1,$2}' /etc/shadow`
if [[ -n $empty_passwd ]]; then
	echo -e "/etc/shadow存在空口令账户：\n"$empty_passwd
else
	echo  "检查/etc/shadow不存在空口令账户"
fi

empty_passwd=`awk -F: '$2!="x" {print $1,$2}' /etc/passwd`
if [[ -n $empty_passwd ]]; then
	echo -e "/etc/passwd存在空口令账户：\n"$empty_passwd
else
	echo  "检查/etc/passwd不存在空口令账户"
fi
echo
echo
echo "------------------------------- 弱口令 -------------------------------"
echo ">>>>>>>>>>>>>>>>>>>> [自行查看是否存在弱口令:] <<<<<<<<<<<<<<<<<<<<"
echo
echo

# 密码策略
echo "-------------------------------口令复杂度策略 -------------------------------"
echo ">>>>>>>>>>>>>>>>>>>> [查看具备口令策略制定哪个配置文件:] <<<<<<<<<<<<<<<<<<<<"
grep  'include' /etc/pam.d/passwd
echo
echo

# 最小口令长度
echo ">>>>>>>>>>>>>>>>>>>> [/etc/pam.d/common-auth文件下的口令最小长度:] <<<<<<<<<<<<<<<<<<<<"
min_len=`more /etc/pam.d/common-auth | grep -E 'pam_pwquality.so'`
if [[ -n $min_len ]];then
	echo -e "/etc/pam.d/common-auth文件下口令最小长度为："$min_len
else
	echo "未配置/etc/pam.d/common-auth文件的口令最小长度"
fi
echo
echo ">>>>>>>>>>>>>>>>>>>> [/etc/security/pwquality.conf文件下的口令最小长度:]"
min_l=`more /etc/security/pwquality.conf | grep -E '\bminlen'`
is_work=`cat /etc/security/pwquality.conf | grep -E 'minlen'|grep -v '^#'`
if [[ -n $is_work ]];then
	echo -e "/etc/security/pwquality.conf文件的口令最小长度:"$is_work
else
	echo "未配置/etc/security/pwquality.conf文件"
fi
echo
echo "（注意：若上述两个文件均存在配置，以/etc/pam.d/common-auth文件为准，下同）"
echo

# 口令复杂度
echo ">>>>>>>>>>>>>>>>>>>> [口令的复杂度:] <<<<<<<<<<<<<<<<<<<<"
complexity=`more /etc/pam.d/common-auth | grep -E 'pam_pwquality.so'`
if [[ -n $complexity ]];then
	echo -e "/etc/pam.d/common-auth文件下口令复杂度为："$complexity
else
	echo "未配置/etc/pam.d/common-auth文件的口令复杂度"
fi
echo ">>>>>>>>>>>>>>>>>>>> [/etc/security/pwquality.conf文件下的口令复杂度:] <<<<<<<<<<<<<<<<<<<<"
echo
is_comp_work=`cat /etc/security/pwquality.conf | grep -E 'minclass|dcredit|ucredit|lcredit|ocredit' |grep -v '^#'`
if [[ -n $is_comp_work ]];then
	echo -e "/etc/security/pwquality.conf文件的口令复杂度:"$is_comp_work
else
	echo "未配置/etc/security/pwquality.conf文件"
fi
echo
echo
echo

# 口令有效期
echo ">>>>>>>>>>>>>>>>>>>> [/etc/login.defs文件下新建账户的口令有效期:] <<<<<<<<<<<<<<<<<<<<"
cat /etc/login.defs | grep PASS_MAX_DAYS | grep -v ^# | awk '{print "PASS_MAX_DAYS = "$2}'
cat /etc/login.defs | grep PASS_MIN_DAYS | grep -v ^# | awk '{print "PASS_MIN_DAYS = "$2}'
cat /etc/login.defs | grep PASS_WARN_AGE | grep -v ^# | awk '{print "PASS_WARN_AGE = "$2}'
echo
echo ">>>>>>>>>>>>>>>>>>>> [/etc/shadow文件下现有账户的有效期:] <<<<<<<<<<<<<<<<<<<<"
awk -F: '$2!="!!" && $2!="*" {print $1,$5}' /etc/shadow
echo
echo


# ************************************ 身份鉴别b） ************************************
echo "************************************ 登录失败处理 ************************************"
echo
echo "------------------------------- 登录失败策略 -------------------------------"
# 登录失败策略
echo ">>>>>>>>>>>>>>>>>>>> [查看/etc/pam.d/system-auth文件下的登录失败策略:] <<<<<<<<<<<<<<<<<<<<"
login_failure=`more /etc/pam.d/system-auth | grep faillock`
if [[ -n $login_failure ]]; then
	echo -e "已设置登录失败策略：\n"$login_failure
else
	echo -e "未设置登录失败策略：\n"$login_failure
fi
echo
echo

# ssh登录失败策略
echo ">>>>>>>>>>>>>>>>>>>> [查看/etc/pam.d/sshd文件下的登录失败策略:] <<<<<<<<<<<<<<<<<<<<"
ssh_login_failure=`cat /etc/pam.d/sshd | grep faillock`
if [[ -n $ssh_login_failure ]]; then
	echo  -e "已设置ssh登录失败策略：\n"$ssh_login_failure
else
	echo -e "未设置ssh登录失败策略：\n"$ssh_login_failure
fi
echo
echo

# 空闲时间超时自动退出
echo "------------------------------- 登录失败策略 -------------------------------"
echo ">>>>>>>>>>>>>>>>>>>> [查看/etc/profile文件下的登录失败策略:] <<<<<<<<<<<<<<<<<<<<"
timeout=`grep TMOUT /etc/profile`
if [[ -n $timeout ]];then
	echo -e "存在/etc/profile文件下的TMOUT值：\n"$timeout
else
	echo "未设置TMOUT值"
fi
echo
echo ">>>>>>>>>>>>>>>>>>>> [查看/root/.bash_profile文件下的登录失败策略:]"
timeout=`grep 'TMOUT' /root/.bash_profile`
if [[ -n $timeout ]];then
	echo -e "存在/root/.bash_profile文件下的TMOUT值：\n"$timeout
else
	echo "未设置TMOUT值"
fi
awk -F: '($7 == "/bin/bash" || $7 == "/bin/sh") {print $1, $6}' /etc/passwd | while IFS=" " read -r user home; do  
    # 检查用户主目录是否存在  
    if [[ -d "$home" ]]; then  
        # 检查.profile文件  
        if [[ -f "$home/.profile" ]]; then  
            timeout_profile=$(grep 'TMOUT' "$home/.profile")  
            if [[ -n "$timeout_profile" ]]; then  
                echo "用户 $user 在 $home/.profile 中设置了TMOUT值："  
                echo -e "$timeout_profile"  
            fi  
        fi  
          
        # 检查.bash_profile文件  
        if [[ -f "$home/.bash_profile" ]]; then  
            timeout_bash_profile=$(grep 'TMOUT' "$home/.bash_profile")  
            if [[ -n "$timeout_bash_profile" ]]; then  
                echo "用户 $user 在 $home/.bash_profile 中设置了TMOUT值："  
                echo -e "$timeout_bash_profile"  
            fi  
        fi  
    fi  
done
echo
echo

# ************************************ 身份鉴别c） ************************************
echo "************************************ 远程登录防窃听 ************************************"
echo
echo "------------------------------- 远程登录管理模式 -------------------------------"
echo ">>>>>>>>>>>>>>>>>>>> [查看是否使用安全的远程登录管理模式:] <<<<<<<<<<<<<<<<<<<<"
Insecurity=`grep '^telnet\|^rlogin' /etc/services`
ssh=`grep '^ssh\b' /etc/services |awk '{print $1,$2}'`

echo -e "使用了安全的协议：" 
if 	[ $?==0 ];then
	for line in "$ssh";do 
	echo $line
	done
else
	echo "未采用SSH安全的协议"
fi
echo
echo
echo -e "可能使用了不安全的协议：" 
if 	[ $?==0 ];then
	for line in "$Insecurity";do
	echo $line
	done
else
	echo  "未使用不安全的协议"
fi
echo
echo

# ************************************ 访问控制a) ************************************
echo "************************************ 访问控制 ************************************"
echo
# 账户分配、权限分配、权限限制
echo ">>>>>>>>>>>>>>>>>>>> [是否对账户进行合理分配:] <<<<<<<<<<<<<<<<<<<<"
echo -e "查看账户列表：\n"`awk -F : '{print $3,$1}' /etc/passwd |sort -n`
echo
echo ">>>>>>>>>>>>>>>>>>>> [是否对默认、匿名账户进行权限限制:]"
echo -e "查看是否限制root账户远程登录的权限：\n"`grep 'PermitRootLogin' /etc/ssh/sshd_config`
echo
echo


# ************************************ 访问控制b) ************************************
echo "************************************ 默认账户名和默认口令 ************************************"
echo
# 默认账户、默认口令
echo ">>>>>>>>>>>>>>>>>>>> [是否重命名、删除或禁用默认账户:] <<<<<<<<<<<<<<<<<<<<"
Default_Account=`grep '^admin\|^tomcat\|^mysql\|^apache\|^clamupdate\|^mariadb\|^nginx\|^shutdown\|^halt ' /etc/passwd`
if [[ -n $Default_Account ]];then
	echo -e "存在默认账户：\n"$Default_Account
else
	echo "未存在默认账户"
fi
echo
echo ">>>>>>>>>>>>>>>>>>>> [自行检查是否为默认口令（可复用弱口令的判定结果）:] <<<<<<<<<<<<<<<<<<<<"
echo
echo

# ************************************ 访问控制c) ************************************
echo "************************************ 多余的、过期的账户 ************************************"
echo
# 对多余帐户进行删除、锁定或禁止其登录如：uucp、nuucp、lp、adm、sync、shutdown、halt、news、operator、gopher用户
echo ">>>>>>>>>>>>>>>>>>>> [是否存在多余的账户:] <<<<<<<<<<<<<<<<<<<<"
excess_account=`awk -F: '{print $1,$3,$6,$7}' /etc/passwd |grep -v 'nologin\|false\|sync'|grep -E 'uucp|nuucp|lp|adm|sync|shutdown|halt|news|operator|gopher'`
if [[ -n $excess_account ]];then
   echo -e "存在多余的账户名：\n"$excess_account
else 
	echo -e "未存在多余的账户名"
fi

# 禁止共享同一个账户
echo
echo ">>>>>>>>>>>>>>>>>>>> [是否存在共享账户:] <<<<<<<<<<<<<<<<<<<<"
echo -e "查看登录日志：\n"`lslogins`
echo  
echo -e "查看账户登录日志:\n"`aureport -au|tail -n 100`
echo

# ************************************ 访问控制d) ************************************
echo "************************************ 角色划分，最小权限 ************************************"
echo
echo ">>>>>>>>>>>>>>>>>>>> [是否限制普通用户的su权限:] <<<<<<<<<<<<<<<<<<<<"
su=`grep 'pam_wheel.so use_uid' /etc/pam.d/su`
# 判断auth required pam_wheel.so use_uid字段行是否被注释
if grep -q "^auth\s\+required\s\+pam_wheel.so\s\+use_uid\s*$" /etc/pam.d/su; then
  echo -e "已限制普通用户执行su命令权限:\n"$su
else
  echo -e "未限制普通用户执行su命令权限:\n"$su
fi
echo
echo ">>>>>>>>>>>>>>>>>>>> [是否合理配置sudo权限:] <<<<<<<<<<<<<<<<<<<<"
# 检测root组是否无口令可登录
sudo_root=`grep '^root' /etc/sudoers`
if grep -q "^%root\s\+ALL=(ALL)\s\+NOPASSWD:\s\+ALL$" /etc/sudoers; then
  echo -e "root组无需口令可登录：\n"$sudo_root
else
  echo -e "未存在root或root组无需口令登录：\n"$sudo_root
fi
echo
# 检测是否存在别的用户组拥有过大的权限
while read line; do
  if [[ "$line" =~ ^%[^:]+ ]]; then
	group=`echo "$line"  |awk  '{print $1}'`
    if grep -q "^$group\s\+ALL=(ALL)\s\+NOPASSWD:\s\+ALL$" /etc/sudoers; then
      echo -e "\n以下组拥有过大的权限\n"$line
		elif grep -q "^$group\s\+ALL=(ALL)\s\+ALL$" /etc/sudoers; then
			echo -e "\n以下组拥有过大的权限\n"$line
		elif grep -q "^$group\s\+ALL=(ALL:ALL)\s\+NOPASSWD:\s\+ALL$" /etc/sudoers; then
			echo -e "\n以下组拥有过大的权限\n"$line
		elif grep -q "^$group\s\+ALL=(ALL:ALL)\s\+ALL$" /etc/sudoers; then
			echo -e "\n以下组拥有过大的权限\n"$line
	else
	echo -e "$line 组未拥有过大的权限\n"
    fi
  fi
done < /etc/sudoers
echo
echo ">>>>>>>>>>>>>>>>> [查看判断是否管理员群组是否存在其他用户:] <<<<<<<<<<<<<<<<<"
# 判断当前组是否仅存在组员
echo -e "$group_name组存在其他成员："
while IFS=: read -r group_name group_passwd group_id group_users; do
  if [[ -n "$group_users" ]]; then
 echo -e "$group_name:$group_users\n"
  fi
done < /etc/group
echo
echo ">>>>>>>>>>>>>>>>> [访问控制分配是否合理:] <<<<<<<<<<<<<<<<<"
echo "核查各重要配置文件和目录权限"
echo -e "`getfacl /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/profile /home/ /etc/systemd/system /etc/xinetd.d`\n"
echo -e "核查账户级umask值:\n"
user_umask=`grep umask /root/.bash_profile`
if [[ -n $user_umask ]];then
	echo "账户级umask值:"$user_umask
else
	echo "未设置账户级umask值"
fi
echo
echo -e "核查账户级umask值:\n"
global_umask=`grep umask /etc/profile`
if [[ -n $global_umask ]];then
	echo "全局umask值:"$global_umask
else
	echo "未设置全局umask值"
fi
echo
echo -e "核查umask值:\n"`umask`
echo
echo ">>>>>>>>>>>>>>>>> [访问控制粒度是否合理(是否开启SELinux):] <<<<<<<<<<<<<<<<<"
SELinux=`sestatus`
if [[ -n $SELinux ]];then
	echo "根据SELinux的具体情况进行判断"$SELinux
else
	echo "未开启SELinux"
fi
echo
echo





# ************************************ 安全审计a） ************************************
echo "************************************ 安全审计 ************************************"
echo
echo
# 查看是否开启系统日志 审计 进程
echo ">>>>>>>>>>>>>>>>> [rsyslog服务是否启用:] <<<<<<<<<<<<<<<<<"
rsyslog=`systemctl status rsyslog |grep "active (running)"`
rsyslog_check=`systemctl status rsyslog |awk 'NR==1,NR==3{print}'`
disable_rsyslog=`systemctl status rsyslog |awk 'NR==1,NR==3{print}'`
if [[ -n $rsyslog ]] ;then
	echo -e "已开启rsyslog服务\n"$rsyslog_check
else
	echo -e "未开启rsyslog服务\n"$disable_rsyslog
fi
echo
echo
echo ">>>>>>>>>>>>>>>>> [audit服务是否启用:] <<<<<<<<<<<<<<<<<"
audit=`systemctl status auditd |grep "active (running)"`
audit_check=`systemctl status auditd |awk 'NR==1,NR==3{print}'`
disable_audit=`systemctl status auditd |grep "inactive"`
if [[ -n $audit ]] ;then
	echo -e "已开启audit服务\n"$audit_check
else
	echo -e "未开启audit服务\n"$disable_audit
fi
echo
echo
# 查看审计规则
echo ">>>>>>>>>>>>>>>>> [查看rsyslog日志规则:] <<<<<<<<<<<<<<<<<"
echo `cat /etc/rsyslog.conf`
echo
echo
echo ">>>>>>>>>>>>>>>>> [查看audit审计规则:] <<<<<<<<<<<<<<<<<"
echo `cat /etc/audit/rules.d/audit.rules`
echo
echo


# ************************************ 安全审计b） ************************************
echo "************************************ 审计时间戳、审计规则 ************************************"
echo ">>>>>>>>>>>>>>>>> [查看系统时间是否准确:] <<<<<<<<<<<<<<<<<"
echo -e "系统时间戳：\n"`date`
echo
echo -e "查看是否存在时间同步：\n"`timedatectl`
echo


# ************************************ 安全审计c） ************************************
echo "************************************ 审计保护、备份 ************************************"
echo ">>>>>>>>>>>>>>>>> [查看是否对/var/log目录下文件进行保护:] <<<<<<<<<<<<<<<<<"
echo `getfacl /var/log/*`
echo
echo
echo ">>>>>>>>>>>>>>>>> [查看是否使用syslog或snmp协议进行传输审计日志:] <<<<<<<<<<<<<<<<<"
echo -e "查看是否配置地址使用syslog协议进行传输：\n"`grep -v '^#\|^$' /etc/rsyslog.conf `
echo
snmp=`systemctl status snmpd |grep "active (running)"`
snmp_check=`systemctl status snmpd |awk 'NR==1,NR==3{print}'`
disable_snmp=`systemctl status snmpd |grep "inactive"`
if [[ -n $snmp ]] ;then
	echo -e "已开启snmp服务\n"$snmp_check
else
	echo -e "未开启snmp服务\n"$disable_snmp
fi
echo
snmp_conf=`grep -v '^#\|^$' /etc/snmp/snmpd.conf`
snmp_conf_check=`systemctl status snmpd |awk 'NR==1,NR==3{print}'`
disable_snmp_conf=`systemctl status snmpd |grep "inactive"`
if [[ -n $snmp_conf ]] ;then
	echo -e "具备snmp配置内容\n"$snmp_conf_check
else
	echo -e "未具备snmp配置内容\n"$disable_snmp_conf
fi
echo
echo ">>>>>>>>>>>>>>>>> [查看是否对审计日志进行保存:] <<<<<<<<<<<<<<<<<"
echo -e "查看主配置文件的日志轮转配置文件:\n"`grep -v '^#\|^$' /etc/logrotate.conf`
echo
echo -e "查看子配置文件的日志轮转配置文件:\n"
for file in /etc/logrotate.d/*; do  
    if [ -f "$file" ]; then  
		echo "子配置文件：$file 内容如下："
        grep -v '^#\|^$' "$file"  
		echo
    fi  
done
echo
echo -e "查看auditd.conf文件配置项:(num_logs不小于2，max_log_file_action = ROTATE)\n"`grep 'max_log_file_action\|num_logs\|max_log_file' /etc/audit/auditd.conf`
echo
echo ">>>>>>>>>>>>>>>>> [查看audit审计日志格式:] <<<<<<<<<<<<<<<<<"
log_format=`grep 'log_format' /etc/audit/auditd.conf`
	echo -e "核查audit审计日志格式log_format设置是否合理：\n"$log_format
echo
echo ">>>>>>>>>>>>>>>>> [查看审计日志保存时间是否满足6个月:] <<<<<<<<<<<<<<<<<"
echo `head  /var/log/audit/audit.log /var/log/secure`
echo 
echo `tail  /var/log/audit/audit.log /var/log/secure`
echo
echo
echo ">>>>>>>>>>>>>>>>> [查看审计日志是否具备备份措施:] <<<<<<<<<<<<<<<<<"
crond=`systemctl status crond |grep "active (running)"`
crond_check=`systemctl status crond |awk 'NR==1,NR==3{print}'`
disable_crond=`systemctl status crond |grep "inactive"`
back_crontab=`crontab -l`
if [[ -n $crond ]] ;then
	echo -e "已开启crond服务\n"$crond_check
else
	echo -e "未开启crond服务\n"$disable_crond
fi
if [[ -n $back_crontab ]];then
	echo -e "检查crontab列表中是否存在定期备份措施：\n"$back_crontab
else
	echo "未配置crontab定时计划任务"
fi
echo 




# ************************************ 入侵防范a） ************************************
echo "************************************ 最小原则 ************************************"
echo
# 检查正在运行的服务，是否有运行无关的进程
echo ">>>>>>>>>>>>>>>>> [最小化安装原则:] <<<<<<<<<<<<<<<<<"
# 检测是否存在 docker
if yum list installed | grep -q docker; then
  # 输出 docker 版本信息
  echo "Docker版本:"
  docker version

  # 输出 docker 容器信息
  echo "Docker容器信息:"
  docker ps
else 
  echo "未安装docker"
fi

# 检测是否存在其他软件包
packages=(
  "samba"
  "bluetooth"
  "telnet-server"
  "rsh"
  "rsh-server"
  "vsftpd"
  "ypbind"
  "tftp-server"
  "bind"
  "cups"
  "nfs-utils"
  "rpcbind"
)

for package in "${packages[@]}"; do
 if yum list installed | grep -q "$package"; then
    echo "$package已安装"
  else 
    echo "$package未安装"
  fi
done
echo
echo

# ************************************ 入侵防范b） ************************************
echo "************************************ 最小服务、高危端口、匿名共享 ************************************"
echo
# 最小化服务
echo ">>>>>>>>>>>>>>>>> [最小化服务:] <<<<<<<<<<<<<<<<<"
minimizes=`grep -E '^smbd|^ftp\b|^telnet\b|^rsh|^rlogin|^cups|^talk|^pop-2|^sendmail|^imap\b|^xinetd' /etc/services |awk '{print$1}'`
if [[ -n $minimizes ]];then
	echo -e "存在多余的、不必要的服务：\n"$minimizes
else
	echo "未存在多余的、不必要的服务"
fi
echo
echo

# samba默认共享
echo ">>>>>>>>>>>>>>>>> [是否存在smaba默认共享:] <<<<<<<<<<<<<<<<<"
samba=`systemctl status smb |grep 'active (running)'`
samba_check=`systemctl status smb |awk 'NR==1,NR==3{print}'`
#disable_samba=`systemctl status smb |grep 'inactive'`
disable_samba_check=`systemctl status smb |awk 'NR==1,NR==3{print}'`
if [[ -n $samba ]] ;then
	echo -e "已开启samba服务\n"$samba_check
else
	echo -e "未开启samba服务\n"$disable_samba_check
fi
echo

echo ">>>>>>>>>>>>>>>>> [检查samba服务是否配置了匿名共享] <<<<<<<<<<<<<<<<<"
is_share=`grep 'security = share\|guest ok =yes \|public = yes' /etc/samba/smb.conf`
if [[ -n $is_share ]];then
	echo -e "配置了samba共享：\n"$is_share
else	
	echo -e "未配置samba匿名共享：\n"$is_share
fi
echo


# NFS默认共享
echo ">>>>>>>>>>>>>>>>> [是否存在NFS默认共享:] <<<<<<<<<<<<<<<<<"
nfs=`systemctl status nfs-serve |grep 'active (exited)'`
nfs_check=`systemctl status nfs |awk 'NR==1,NR==3{print}'`
disable_nfs_check=`systemctl status nfs |awk 'NR==1,NR==3{print}'`
if [[ -n $nfs ]] ;then
	echo -e "已开启NFS服务\n"$nfs_check
else
	echo -e "未开启NFS服务\n"$disable_nfs_check
fi
echo
echo
echo ">>>>>>>>>>>>>>>>> [检查NFS服务是否配置了匿名共享] <<<<<<<<<<<<<<<<<"
share_doc=`grep -v '^$\|^#' /etc/exports`
if [[ -n $share_doc ]];then
	echo -e "配置了NFS共享：\n"$share_doc
else	
	echo -e "未配置NFS匿名共享：\n"$share_doc
fi
echo

# 检测高危端口是否被禁用
echo ">>>>>>>>>>>>>>>>> [检查是否存在高危端口：] <<<<<<<<<<<<<<<<<"
ports=(
  "21"
  "23"
  "25"
  "110"
  "111"
  "137"
  "135"
  "427"
  "445"
  "631"
)
for port in "${ports[@]}"; do
  if netstat -antlp | grep -q ":$port\b"; then
    echo "$port端口已启用"
    if iptables -nv -L | grep -q ":$port\b"; then
      if iptables -nv -L | grep -q "ACCEPT.*:$port\b"; then
        echo -e "防火墙允许$port端口通信\n"
      elif iptables -nv -L | grep -q "DROP.*:$port\b"; then
        echo -e "防火墙禁止$port端口通信\n"
      elif iptables -nv -L | grep -q "REJECT.*:$port\b"; then
        echo -e "防火墙拒绝$port端口通信\n"
      else
        echo -e "防火墙未禁止$port端口\n"
      fi
    else
      echo -e "防火墙未禁止$port端口\n"
    fi
  fi
done
echo
# ************************************ 入侵防范c） ************************************
echo "************************************ 管理地址限制 ************************************"
echo
echo ">>>>>>>>>>>>>>>>> [centos8弃用/etc/hosts.deny和/etc/hosts.allow文件进行限制:] <<<<<<<<<<<<<<<<<"
echo
echo ">>>>>>>>>>>>>>>>> [防火墙规则查看:] <<<<<<<<<<<<<<<<<"
echo `firewall-cmd --list-all`
echo

# ************************************ 入侵防范e） ************************************
echo "************************************ 安全漏洞管理 ************************************"
echo
echo ">>>>>>>>>>>>>>>>> [查看系统版本信息是否存在安全漏洞:] <<<<<<<<<<<<<<<<<"
echo -e " 系统版本:\t "`cat /etc/redhat-release`
echo -e " 内核版本:\t "`uname -a`
echo

echo ">>>>>>>>>>>>>>>>> [查看系统安装补丁情况：] <<<<<<<<<<<<<<<<<"
patchinfo=`rpm -qa --last | grep patch`
if [ -n "$patchinfo" ]; then
	echo  -e "存在以下已安装的补丁：\n"$patchinfo
else
	echo "未存在补丁安装包"
fi
echo
echo
# ************************************ 入侵防范f） ************************************
echo "************************************ 入侵防范措施 ************************************"
echo
echo ">>>>>>>>>>>>>>>>> [查看是否具备入侵检测措施：] <<<<<<<<<<<<<<<<<"
echo -e "访谈管理员是否存在入侵检测措施："
echo "如CrowdStrike Falcon、EventLog Analyzer、OSSEC、Sagan、Security Onion（Linux）、AIDE、Samhain、Fail2Ban等"
echo
echo




# ************************************ 恶意代码防范 ************************************
echo "************************************ 恶意代码防范 ************************************"
echo
echo ">>>>>>>>>>>>>>>>> [查看是否安装了恶意代码防范措施:] <<<<<<<<<<<<<<<<<"
clam=`clamscan -V 2>/dev/null`
if [[ -n $clam ]];then
	echo -e "已安装clamav，其版本号为："$clam
else
	echo "未安装clamav"
fi
echo


echo ">>>>>>>>>>>>>>>>> [查看是否配置了计划任务定期查杀病毒：] <<<<<<<<<<<<<<<<<"
clam_crontab=`crontab -l | grep clamscan`
if [[ -n $clam_crontab ]];then
  echo -e "已配置clamav定时计划任务进行查杀：\n"$clam_crontab
else
  echo -e "未配置clamav定时计划任务进行查杀"
 fi
 echo
freshclam=`crontab -l | grep freshclam`
if [[ -n $freshclam ]];then
    echo -e "已计划定时更新clamav病毒库：\n"$freshclam
else
	echo -e "未计划定时更新clamav病毒库"
  fi

echo
echo -e "访谈管理员是否存在其他恶意代码防范措施："
echo "如safedog、kingsoft等"
echo
echo

echo
# ************************************ 数据安全 ************************************
echo "************************************ 重要数据的完整性和重要数据的备份恢复 ************************************"
echo 
# 查看/var/spool/cron文件下是否具备其他的计划任务
echo ">>>>>>>>>>>>>>>>> [查看/var/spool/cron/目录下是否存在其他crontab文件:] <<<<<<<<<<<<<<<<<"
echo
cron=`ls /var/spool/cron`
if [[ -n $cron ]];then
	echo -e "当前存在其他的定时计划任务：\n"$cron
else
	echo "该目录为空，无其他人员的定时计划任务"
fi
echo
# 获取用户输入的安全管理员账户名
echo ">>>>>>>>>>>>>>>>> [查看其他管理员的crontab文件:] <<<<<<<<<<<<<<<<<"
read -p  "请输入其他管理员账户名：" users
echo
# 执行runuser命令
echo -e "查看其他管理员$users创建的定时计划任务内容:\n"
runuser -l $users -c " crontab -l"
echo
echo


# ************************************ 数据安全 ************************************
echo "************************************ 剩余信息保护 ************************************"
echo
echo ">>>>>>>>>>>>>>>>> [查看是否留存历史记录：] <<<<<<<<<<<<<<<<<"
echo
bash_history=`head -n 10 ~/.bash_history`
echo 
echo -e "查看是否保存历史记录信息：\n"$bash_history
echo
echo
echo ">>>>>>>>>>>>>>>>> [查看/etc/profile下的HISTSIZE和HISTFILESIZE的配置值：] <<<<<<<<<<<<<<<<<"
hist=`grep 'HISTSIZE\|HISTFILESIZE' /etc/profile`
if [[ -n $hist ]];then
	echo -e "查看保存历史记录信息记录总数：\n"$hist
else
	echo "未设置保存历史记录数"
echo
fi
echo ">>>>>>>>>>>>>>>>> [查看~/.bash_history文件下的HISTSIZE和HISTFILESIZE的配置值：] <<<<<<<<<<<<<<<<<"
username=$(whoami)
echo "当前登录的用户名为："$username

## hist_user=`grep 'HISTSIZE\|HISTFILESIZE' /$username/.bash_history`
if [[ -n $hist ]];then
	echo -e "查看保存历史记录信息记录总数：\n"grep 'HISTSIZE\|HISTFILESIZE' /$username/.bash_history
else
	echo "未设置保存历史记录数"
echo
fi

}


#################################################### Ubuntu20.04 ###########################################################
Ubuntu20.04(){
IFS=""

# ************************************ 重定向到输出文件 ************************************
# 重定向的说明，询问是否使用重定向到指定目录文件
read -p "请问是否需要将测评结果输出到/var/exam/{os}.txt？[yes/no]" redirects
if [[ $redirects = "yes" ]] ||  [[ $redirects = "y" ]];then
	mkdir -p /var/exam/
	touch /var/exam/ubuntu20.04_$(date +%Y-%m-%d\ %H:%M:%S).txt
	redirects_catalogs="/var/exam/ubuntu20.04_$(date +%Y-%m-%d\ %H:%M:%S).txt"
	exec >"$redirects_catalogs"
fi

echo "# ---------------------------------------------------------------------"
echo -e "# 简介: \t 检查Linux-Ubuntu20.04-安全计算环境-4级" 
echo -e "# 系统时间:\t "`date +'%Y-%m-%d %H:%S'`
echo -e "# 系统版本:\t "`lsb_release -d`
echo -e "# 内核版本:\t "`uname -a`
echo "# ---------------------------------------------------------------------"
echo



# 系统IP地址
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> [IP地址:] <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
echo -e "主机名: \t\t" `hostname -s`
echo -e "IP地址: \t\t " `ifconfig | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -v 127 | awk '{print $2}'` 
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
echo


# ************************************ 身份鉴别a） ************************************
echo "************************************ 身份鉴别 ************************************"
echo
echo
echo "------------------------------- 身份鉴别措施 -------------------------------"
echo
# 是否具备身份鉴别措施
echo ">>>>>>>>>>>>>>>>>>>> [是否存在自动登录鉴别措施:] <<<<<<<<<<<<<<<<<<<<"

Authentication=`grep 'AutomaticLoginEnable\|AutomaticLogin' /etc/gdm3/custom.conf`
if [[ -n $Authentication ]]; then
	echo $Authentication
else
	echo "没有设置自动登录的账户"
fi
echo
echo

#是否存在rsh服务
echo ">>>>>>>>>>>>>>>>>>>> [是否存在rsh-server远程登录管理服务:] <<<<<<<<<<<<<<<<<<<<"
rsh=`dpkg -l |grep -i 'rsh'`
if [[ -n $rsh ]]; then
	echo -e "安装了rsh远程管理服务:\n"$rsh
else
	echo "未安装rsh远程登录管理服务"
fi
echo

# 是否配置了rsh服务
echo ">>>>>>>>>>>>>>>>>>>> [是否配置rsh-server远程登录管理服务:] <<<<<<<<<<<<<<<<<<<<"
rhosts=`find /root -name .rhosts -print -exec cat {} \;`
equiv=`find /etc -name hosts.equiv -print -exec cat {} \;`
if [[ -n $rhosts ]]; then
	echo $rhosts
else
	echo $equiv
fi
echo

echo ">>>>>>>>>>>>>>>>>>>> [/etc/pam.d/sshd是否存在pam.listfile.so认证模块:] <<<<<<<<<<<<<<<<<<<<"
listfile=`grep 'pam.listfile.so' /etc/pam.d/sshd`
if [[ -n $listfile ]]; then
	echo -e "配置了pam.listfile.so认证模块:\n" $listfile
else
	echo "未配置pam.listfile.so认证模块"
fi
echo
echo
echo
echo

echo "------------------------------- 身份标识唯一性 -------------------------------"
echo ">>>>>>>>>>>>>>>>>>>> [身份标识唯一性是否仅存在root账户UID=0:] <<<<<<<<<<<<<<<<<<<<"
#是否仅存在root账户的UID=0
uid=`awk -F: '($3==0)' /etc/passwd |grep -v 'root'`
if [[ -n $uid ]];then
	echo -e "存在除root账户外UID为0的账户:\n"$uid
else
	echo "仅存在root账户的UID为0"
fi
echo

# 是否有空口令 
echo "------------------------------- 空口令 -------------------------------"
echo ">>>>>>>>>>>>>>>>>>>> [是否存在空口令账户:] <<<<<<<<<<<<<<<<<<<<"
empty_passwd=`awk -F: 'length($2)==0 {print $1,$2}' /etc/shadow`
if [[ -n $empty_passwd ]]; then
	echo -e "/etc/shadow存在空口令账户：\n"$empty_passwd
else
	echo  "检查/etc/shadow不存在空口令账户"
fi

empty_passwd=`awk -F: '$2!="x" {print $1,$2}' /etc/passwd`
if [[ -n $empty_passwd ]]; then
	echo -e "/etc/passwd存在空口令账户：\n"$empty_passwd
else
	echo  "检查/etc/passwd不存在空口令账户"
fi
echo
echo
echo "------------------------------- 弱口令 -------------------------------"
echo ">>>>>>>>>>>>>>>>>>>> [自行查看是否存在弱口令:] <<<<<<<<<<<<<<<<<<<<"
echo
echo

# 密码策略
echo "-------------------------------口令复杂度策略 -------------------------------"
echo ">>>>>>>>>>>>>>>>>>>> [查看具备口令策略制定哪个配置文件:] <<<<<<<<<<<<<<<<<<<<"
grep  'include' /etc/pam.d/passwd
echo
echo

# 最小口令长度
echo ">>>>>>>>>>>>>>>>>>>> [/etc/pam.d/common-auth文件下的口令最小长度:] <<<<<<<<<<<<<<<<<<<<"
min_len=`more /etc/pam.d/common-auth | grep -E 'pam_pwquality.so'`
if [[ -n $min_len ]];then
	echo -e "/etc/pam.d/common-auth文件下口令最小长度为："$min_len
else
	echo "未配置/etc/pam.d/common-auth文件的口令最小长度"
fi
echo
echo ">>>>>>>>>>>>>>>>>>>> [/etc/security/pwquality.conf文件下的口令最小长度:]"
min_l=`more /etc/security/pwquality.conf | grep -E '\bminlen'`
is_work=`cat /etc/security/pwquality.conf | grep -E 'minlen'|grep -v '^#'`
if [[ -n $is_work ]];then
	echo -e "/etc/security/pwquality.conf文件的口令最小长度:"$is_work
else
	echo "未配置/etc/security/pwquality.conf文件"
fi
echo
echo "（注意：若上述两个文件均存在配置，以/etc/pam.d/common-auth文件为准，下同）"
echo

# 口令复杂度
echo ">>>>>>>>>>>>>>>>>>>> [口令的复杂度:] <<<<<<<<<<<<<<<<<<<<"
complexity=`more /etc/pam.d/common-auth | grep -E 'pam_pwquality.so'`
if [[ -n $complexity ]];then
	echo -e "/etc/pam.d/common-auth文件下口令复杂度为："$complexity
else
	echo "未配置/etc/pam.d/common-auth文件的口令复杂度"
fi
echo ">>>>>>>>>>>>>>>>>>>> [/etc/security/pwquality.conf文件下的口令复杂度:] <<<<<<<<<<<<<<<<<<<<"
echo
is_comp_work=`cat /etc/security/pwquality.conf | grep -E 'minclass|dcredit|ucredit|lcredit|ocredit' |grep -v '^#'`
if [[ -n $is_comp_work ]];then
	echo -e "/etc/security/pwquality.conf文件的口令复杂度:"$is_comp_work
else
	echo "未配置/etc/security/pwquality.conf文件"
fi
echo
echo
echo

# 口令有效期
echo ">>>>>>>>>>>>>>>>>>>> [/etc/login.defs文件下新建账户的口令有效期:] <<<<<<<<<<<<<<<<<<<<"
cat /etc/login.defs | grep PASS_MAX_DAYS | grep -v ^# | awk '{print "PASS_MAX_DAYS = "$2}'
cat /etc/login.defs | grep PASS_MIN_DAYS | grep -v ^# | awk '{print "PASS_MIN_DAYS = "$2}'
cat /etc/login.defs | grep PASS_WARN_AGE | grep -v ^# | awk '{print "PASS_WARN_AGE = "$2}'
echo
echo ">>>>>>>>>>>>>>>>>>>> [/etc/shadow文件下现有账户的有效期:] <<<<<<<<<<<<<<<<<<<<"
awk -F: '$2!="!!" && $2!="*" {print $1,$5}' /etc/shadow
echo
echo


# ************************************ 身份鉴别b） ************************************
echo "************************************ 登录失败处理 ************************************"
echo
echo "------------------------------- 登录失败策略 -------------------------------"
# 登录失败策略
echo ">>>>>>>>>>>>>>>>>>>> [查看/etc/pam.d/common-auth文件下的登录失败策略:] <<<<<<<<<<<<<<<<<<<<"
login_failure=`more /etc/pam.d/common-auth | grep faillock`
if [[ -n $login_failure ]]; then
	echo -e "已设置登录失败策略：\n"$login_failure
else
	echo -e "未设置登录失败策略：\n"$login_failure
fi
echo
echo

# ssh登录失败策略
echo ">>>>>>>>>>>>>>>>>>>> [查看/etc/pam.d/sshd文件下的登录失败策略:] <<<<<<<<<<<<<<<<<<<<"
ssh_login_failure=`cat /etc/pam.d/sshd | grep faillock`
if [[ -n $ssh_login_failure ]]; then
	echo  -e "已设置ssh登录失败策略：\n"$ssh_login_failure
else
	echo -e "未设置ssh登录失败策略：\n"$ssh_login_failure
fi
echo
echo

# 空闲时间超时自动退出
echo "------------------------------- 登录失败策略 -------------------------------"
echo ">>>>>>>>>>>>>>>>>>>> [查看/etc/profile文件下的登录失败策略:] <<<<<<<<<<<<<<<<<<<<"
timeout=`grep TMOUT /etc/profile`
if [[ -n $timeout ]];then
	echo -e "存在/etc/profile文件下的TMOUT值：\n"$timeout
else
	echo "未设置TMOUT值"
fi
echo
echo ">>>>>>>>>>>>>>>>>>>> [查看/root/.bash_profile文件下的登录失败策略:]"
timeout=`grep 'TMOUT' /root/.profile`
if [[ -n $timeout ]];then
	echo -e "存在/root/.bash_profile文件下的TMOUT值：\n"$timeout
else
	echo "未设置TMOUT值"
fi
awk -F: '($7 == "/bin/bash" || $7 == "/bin/sh") {print $1, $6}' /etc/passwd | while IFS=" " read -r user home; do  
    # 检查用户主目录是否存在  
    if [[ -d "$home" ]]; then  
        # 检查.profile文件  
        if [[ -f "$home/.profile" ]]; then  
            timeout=$(grep 'TMOUT' "$home/.profile")  
            if [[ -n "$timeout" ]]; then  
                echo "用户 $user 在 $home/.profile 中设置了TMOUT值："  
                echo -e "$timeout"  
            fi  
        fi  
          
        # 检查.bash_profile文件  
        if [[ -f "/etc/bashrc" ]]; then  
            timeout=$(grep 'TMOUT' "/etc/bashrc")  
            if [[ -n "$timeout" ]]; then  
                echo "用户 $user 在 /etc/bashrc 中设置了TMOUT值："  
                echo -e "$timeout"  
            fi  
        fi  
    fi  
done
echo
echo

# ************************************ 身份鉴别c） ************************************
echo "************************************ 远程登录防窃听 ************************************"
echo
echo "------------------------------- 远程登录管理模式 -------------------------------"
echo ">>>>>>>>>>>>>>>>>>>> [查看是否使用安全的远程登录管理模式:] <<<<<<<<<<<<<<<<<<<<"
Insecurity=`grep '^telnet\|^rlogin' /etc/services`
ssh=`grep '^ssh\b' /etc/services |awk '{print $1,$2}'`

echo -e "使用了安全的协议：" 
if 	[ $?==0 ];then
	for line in "$ssh";do 
	echo $line
	done
else
	echo "未采用SSH安全的协议"
fi
echo
echo
echo -e "可能使用了不安全的协议：" 
if 	[ $?==0 ];then
	for line in "$Insecurity";do
	echo $line
	done
else
	echo  "未使用不安全的协议"
fi
echo
echo

# ************************************ 访问控制a) ************************************
echo "************************************ 访问控制 ************************************"
echo
# 账户分配、权限分配、权限限制
echo ">>>>>>>>>>>>>>>>>>>> [是否对账户进行合理分配:] <<<<<<<<<<<<<<<<<<<<"
echo -e "查看账户列表：\n"`awk -F : '{print $3,$1}' /etc/passwd |sort -n`
echo
echo ">>>>>>>>>>>>>>>>>>>> [是否对默认、匿名账户进行权限限制:]"
echo -e "查看是否限制root账户远程登录的权限：\n"`grep 'PermitRootLogin' /etc/ssh/sshd_config`
echo
echo


# ************************************ 访问控制b) ************************************
echo "************************************ 默认账户名和默认口令 ************************************"
echo
# 默认账户、默认口令
echo ">>>>>>>>>>>>>>>>>>>> [是否重命名、删除或禁用默认账户:] <<<<<<<<<<<<<<<<<<<<"
Default_Account=`grep '^admin\|^tomcat\|^mysql\|^apache\|^clamupdate\|^mariadb\|^nginx\|^shutdown\|^halt ' /etc/passwd`
if [[ -n $Default_Account ]];then
	echo -e "存在默认账户：\n"$Default_Account
else
	echo "未存在默认账户"
fi
echo
echo ">>>>>>>>>>>>>>>>>>>> [自行检查是否为默认口令（可复用弱口令的判定结果）:] <<<<<<<<<<<<<<<<<<<<"
echo
echo

# ************************************ 访问控制c) ************************************
echo "************************************ 多余的、过期的账户 ************************************"
echo
# 对多余帐户进行删除、锁定或禁止其登录如：uucp、nuucp、lp、adm、sync、shutdown、halt、news、operator、gopher用户
echo ">>>>>>>>>>>>>>>>>>>> [是否存在多余的账户:] <<<<<<<<<<<<<<<<<<<<"
excess_account=`awk -F: '{print $1,$3,$6,$7}' /etc/passwd |grep -v 'nologin\|false\|sync'|grep -E '^uucp|^nuucp$|^lp$|^adm$|^sync$|^shutdown$|^halt$|^news$|^operator$|^gopher$'`
if [[ -n $excess_account ]];then
   echo -e "存在多余的账户名：\n"$excess_account
else 
	echo -e "未存在多余的账户名"
fi

# 禁止共享同一个账户
echo
echo ">>>>>>>>>>>>>>>>>>>> [是否存在共享账户:] <<<<<<<<<<<<<<<<<<<<"
echo -e "查看登录日志：\n"`lslogins`
echo  
echo -e "查看账户登录日志(tty模式):\n"`lastlog`
echo

# ************************************ 访问控制d) ************************************
echo "************************************ 角色划分，最小权限 ************************************"
echo
echo ">>>>>>>>>>>>>>>>>>>> [是否限制普通用户的su权限:] <<<<<<<<<<<<<<<<<<<<"
su=`grep 'pam_wheel.so' /etc/pam.d/su`
# 判断auth required pam_wheel.so use_uid字段行是否被注释
if grep -q "^auth\s\+required\s\+pam_wheel.so\s*$" /etc/pam.d/su; then
  echo -e "已限制普通用户执行su命令权限:\n"$su
else
  echo -e "未限制普通用户执行su命令权限:\n"$su
fi
echo
echo ">>>>>>>>>>>>>>>>>>>> [是否合理配置sudo权限:] <<<<<<<<<<<<<<<<<<<<"
# 检测root组是否无口令可登录
sudo_root=`grep '^root' /etc/sudoers`
if grep -q "^%root\s\+ALL=(ALL)\s\+NOPASSWD:\s\+ALL$" /etc/sudoers; then
  echo -e "root组无需口令可登录：\n"$sudo_root
else
  echo -e "未存在root或root组无需口令登录：\n"$sudo_root
fi
echo
# 检测是否存在别的用户组拥有过大的权限
while read line; do
  if [[ "$line" =~ ^%[^:]+ ]]; then
	group=`echo "$line"  |awk  '{print $1}'`
    if grep -q "^$group\s\+ALL=(ALL)\s\+NOPASSWD:\s\+ALL$" /etc/sudoers; then
      echo -e "\n以下组拥有过大的权限\n"$line
		elif grep -q "^$group\s\+ALL=(ALL)\s\+ALL$" /etc/sudoers; then
			echo -e "\n以下组拥有过大的权限\n"$line
		elif grep -q "^$group\s\+ALL=(ALL:ALL)\s\+NOPASSWD:\s\+ALL$" /etc/sudoers; then
			echo -e "\n以下组拥有过大的权限\n"$line
		elif grep -q "^$group\s\+ALL=(ALL:ALL)\s\+ALL$" /etc/sudoers; then
			echo -e "\n以下组拥有过大的权限\n"$line
	else
	echo -e "$line 组未拥有过大的权限\n"
    fi
  fi
done < /etc/sudoers
echo
echo ">>>>>>>>>>>>>>>>> [查看判断是否管理员群组是否存在其他用户:] <<<<<<<<<<<<<<<<<"
# 判断当前组是否仅存在组员
echo -e "$group_name组存在其他成员："
while IFS=: read -r group_name group_passwd group_id group_users; do   ##分隔符是：
  if [[ -n "$group_users" ]]; then
 echo -e "$group_name:$group_users\n"
  fi
done < /etc/group
echo
echo ">>>>>>>>>>>>>>>>> [访问控制分配是否合理:] <<<<<<<<<<<<<<<<<"
echo "核查各重要配置文件和目录权限"
echo -e "`getfacl /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/profile /home/ /etc/systemd/system /etc/xinetd.d`\n"
echo
echo -e "核查账户级umask值:\n"
user_umask=`grep umask /root/.bash_profile`
if [[ -n $user_umask ]];then
	echo "账户级umask值:"$user_umask
else
	echo "未设置账户级umask值"
fi
echo
echo -e "核查账户级umask值:\n"
global_umask=`grep umask /etc/profile`
if [[ -n $global_umask ]];then
	echo "全局umask值:"$global_umask
else
	echo "未设置全局umask值"
fi
echo
echo -e "核查umask值:\n"`umask`
echo 
echo
echo ">>>>>>>>>>>>>>>>> [访问控制粒度是否合理(是否开启SELinux):] <<<<<<<<<<<<<<<<<"
SELinux=`sestatus`
if [[ -n $SELinux ]];then
	echo "根据SELinux的具体情况进行判断"$SELinux
else
	echo "未开启SELinux"
fi
echo
echo





# ************************************ 安全审计a） ************************************
echo "************************************ 安全审计 ************************************"
echo
echo
# 查看是否开启系统日志 审计 进程
echo ">>>>>>>>>>>>>>>>> [rsyslog服务是否启用:] <<<<<<<<<<<<<<<<<"
rsyslog=`systemctl status rsyslog |grep "active (running)"`
rsyslog_check=`systemctl status rsyslog |awk 'NR==1,NR==3{print}'`
disable_rsyslog=`systemctl status rsyslog |awk 'NR==1,NR==3{print}'`
if [[ -n $rsyslog ]] ;then
	echo -e "已开启rsyslog服务\n"$rsyslog_check
else
	echo -e "未开启rsyslog服务\n"$disable_rsyslog
fi
echo
echo
echo ">>>>>>>>>>>>>>>>> [audit服务是否启用:] <<<<<<<<<<<<<<<<<"
audit=`systemctl status auditd |grep "active (running)"`
audit_check=`systemctl status auditd |awk 'NR==1,NR==3{print}'`
disable_audit=`systemctl status auditd |grep "inactive"`
if [[ -n $audit ]] ;then
	echo -e "已开启audit服务\n"$audit_check
else
	echo -e "未开启audit服务\n"$disable_audit
fi
echo
echo
# 查看审计规则
echo ">>>>>>>>>>>>>>>>> [查看rsyslog日志规则:] <<<<<<<<<<<<<<<<<"
echo `cat /etc/rsyslog.d/50-default.conf`
echo
echo
echo ">>>>>>>>>>>>>>>>> [查看audit审计规则:] <<<<<<<<<<<<<<<<<"
echo `cat /etc/audit/auditd.conf`
echo
echo


# ************************************ 安全审计b） ************************************
echo "************************************ 审计时间戳、审计规则 ************************************"
echo ">>>>>>>>>>>>>>>>> [查看系统时间是否准确:] <<<<<<<<<<<<<<<<<"
echo -e "系统时间戳：\n"`date`
echo
echo -e "查看是否存在时间同步：\n"`timedatectl`
echo


# ************************************ 安全审计c） ************************************
echo "************************************ 审计保护、备份 ************************************"
echo ">>>>>>>>>>>>>>>>> [查看是否对/var/log目录下文件进行保护:] <<<<<<<<<<<<<<<<<"
echo `getfacl /var/log/*`
echo
echo
echo ">>>>>>>>>>>>>>>>> [查看是否使用syslog或snmp协议进行传输审计日志:] <<<<<<<<<<<<<<<<<"
echo -e "查看是否配置地址使用syslog协议进行传输：\n"`grep -v '^#\|^$' /etc/rsyslog.conf `
echo
snmp=`systemctl status snmpd |grep "active (running)"`
snmp_check=`systemctl status snmpd |awk 'NR==1,NR==3{print}'`
disable_snmp=`systemctl status snmpd |grep "inactive"`
if [[ -n $snmp ]] ;then
	echo -e "已开启snmp服务\n"$snmp_check
else
	echo -e "未开启snmp服务\n"$disable_snmp
fi
echo
snmp_conf=`grep -v '^#\|^$' /etc/snmp/snmpd.conf`
snmp_conf_check=`systemctl status snmpd |awk 'NR==1,NR==3{print}'`
disable_snmp_conf=`systemctl status snmpd |grep "inactive"`
if [[ -n $snmp_conf ]] ;then
	echo -e "已开启snmp服务\n"$snmp_conf_check
else
	echo -e "未开启snmp服务\n"$disable_snmp_conf
fi
echo
echo ">>>>>>>>>>>>>>>>> [查看是否对审计日志进行保存:] <<<<<<<<<<<<<<<<<"
echo -e "查看主配置文件的日志轮转配置文件:\n"`grep -v '^#\|^$' /etc/logrotate.conf`
echo
echo -e "查看子配置文件的日志轮转配置文件:\n"
for file in /etc/logrotate.d/*; do  
    if [ -f "$file" ]; then  
		echo "子配置文件：$file 内容如下："
        grep -v '^#\|^$' "$file"  
		echo
    fi  
done
echo
echo -e "查看auditd.conf文件配置项:(num_logs不小于2，max_log_file_action = ROTATE)\n"`grep 'max_log_file_action\|num_logs\|max_log_file' /etc/audit/auditd.conf`
echo
echo ">>>>>>>>>>>>>>>>> [查看audit审计日志格式:] <<<<<<<<<<<<<<<<<"
log_format=`grep 'log_format' /etc/audit/auditd.conf`
	echo -e "核查audit审计日志格式log_format设置是否合理：\n"$log_format
echo
echo ">>>>>>>>>>>>>>>>> [查看审计日志保存时间是否满足6个月:] <<<<<<<<<<<<<<<<<"
echo `head  /var/log/audit/audit.log /var/log/syslog`
echo 
echo `tail  /var/log/audit/audit.log /var/log/syslog`
echo
echo
echo ">>>>>>>>>>>>>>>>> [查看审计日志是否具备备份措施:] <<<<<<<<<<<<<<<<<"
back_crontab=`crontab -l`
if [[ -n $back_crontab ]];then
	echo -e "检查crontab列表中是否存在定期备份措施：\n"$back_crontab
else
	echo "未配置crontab定时计划任务"
fi
echo 




# ************************************ 入侵防范a） ************************************
echo "************************************ 最小原则 ************************************"
echo
# 检查正在运行的服务，是否有运行无关的进程
echo ">>>>>>>>>>>>>>>>> [最小化安装原则:] <<<<<<<<<<<<<<<<<"
# 检测是否存在 docker
if dpkg --get-selections | grep -q docker; then
  # 输出 docker 版本信息
  echo "Docker版本:"
  docker version

  # 输出 docker 容器信息
  echo "Docker容器信息:"
  docker ps
else 
  echo "未安装docker"
fi

# 检测是否存在其他软件包
packages=(
  "samba"
  "bluetooth"
  "telnet-server"
  "rsh"
  "rsh-server"
  "vsftpd"
  "ypbind"
  "tftp-server"
  "bind"
  "cups"
  "nfs-utils"
  "rpcbind"
)

for package in "${packages[@]}"; do
 if dpkg --get-selections | grep -q "$package"; then
    echo "$package已安装"
  else 
    echo "$package未安装"
  fi
done
echo
echo

# ************************************ 入侵防范b） ************************************
echo "************************************ 最小服务、高危端口、匿名共享 ************************************"
echo
# 最小化服务
echo ">>>>>>>>>>>>>>>>> [最小化服务:] <<<<<<<<<<<<<<<<<"
minimizes=`grep -E '^smbd|^ftp\b|^telnet\b|^rsh|^rlogin|^cups|^talk|^pop-2|^sendmail|^imap\b|^xinetd' /etc/services |awk '{print$1}'`
if [[ -n $minimizes ]];then
	echo -e "存在多余的、不必要的服务：\n"$minimizes
else
	echo "未存在多余的、不必要的服务"
fi
echo
echo

# samba默认共享
echo ">>>>>>>>>>>>>>>>> [是否存在smaba默认共享:] <<<<<<<<<<<<<<<<<"
samba=`systemctl status smb |grep 'active (running)'`
samba_check=`systemctl status smb |awk 'NR==1,NR==3{print}'`
#disable_samba=`systemctl status smb |grep 'inactive'`
disable_samba_check=`systemctl status smb |awk 'NR==1,NR==3{print}'`
if [[ -n $samba ]] ;then
	echo -e "已开启samba服务\n"$samba_check
else
	echo -e "未开启samba服务\n"$disable_samba_check
fi
echo

echo ">>>>>>>>>>>>>>>>> [检查samba服务是否配置了匿名共享] <<<<<<<<<<<<<<<<<"
is_share=`grep 'security = share\|guest ok =yes \|public = yes' /etc/samba/smb.conf`
if [[ -n $is_share ]];then
	echo -e "配置了samba共享：\n"$is_share
else	
	echo -e "未配置samba匿名共享：\n"$is_share
fi
echo


# nfs默认共享
echo ">>>>>>>>>>>>>>>>> [是否存在nfs默认共享:] <<<<<<<<<<<<<<<<<"
nfs=`systemctl status nfs-serve |grep 'active (exited)'`
nfs_check=`systemctl status nfs |awk 'NR==1,NR==3{print}'`
disable_nfs_check=`systemctl status nfs |awk 'NR==1,NR==3{print}'`
if [[ -n $nfs ]] ;then
	echo -e "已开启nfs服务\n"$nfs_check
else
	echo -e "未开启nfs服务\n"$disable_nfs_check
fi
echo
echo
echo ">>>>>>>>>>>>>>>>> [检查nfs服务是否配置了匿名共享] <<<<<<<<<<<<<<<<<"
share_doc=`grep -v '^$\|^#' /etc/exports`
if [[ -n $share_doc ]];then
	echo -e "配置了nfs共享：\n"$share_doc
else	
	echo -e "未配置nfs匿名共享：\n"$share_doc
fi
echo

# 检测高危端口是否被禁用
echo ">>>>>>>>>>>>>>>>> [检查是否存在高危端口：] <<<<<<<<<<<<<<<<<"
ports=(
  "21"
  "23"
  "25"
  "110"
  "111"
  "137"
  "135"
  "139"
  "427"
  "445"
  "631"
)
for port in "${ports[@]}"; do
  if netstat -antlp | grep -q ":$port\b"; then
    echo "$port端口已启用"
    if iptables -nv -L | grep -q ":$port\b"; then
      if iptables -nv -L | grep -q "ACCEPT.*:$port\b"; then
        echo -e "防火墙允许$port端口通信\n"
      elif iptables -nv -L | grep -q "DROP.*:$port\b"; then
        echo -e "防火墙禁止$port端口通信\n"
      elif iptables -nv -L | grep -q "REJECT.*:$port\b"; then
        echo -e "防火墙拒绝$port端口通信\n"
      else
        echo -e "防火墙未禁止$port端口\n"
      fi
    else
      echo -e "防火墙未禁止$port端口\n"
    fi
  fi
done
echo
# ************************************ 入侵防范c） ************************************
echo "************************************ 管理地址限制 ************************************"
echo
echo ">>>>>>>>>>>>>>>>> [查看/etc/hosts.deny和/etc/hosts.allow文件:] <<<<<<<<<<<<<<<<<"
echo
hosts_allow=`grep -v '^#\|^$' /etc/hosts.allow`
hosts_deny=`grep -v '^#\|^$' /etc/hosts.deny`
if [[ -n $hosts_allow ]];then
	echo	-e "/etc/hosts.allow文件的内容:\n"$hosts_allow
else
	echo "未配置/etc/hosts.allow文件，内容为空"
fi
echo
if [[ -n $hosts_deny ]];then
	echo	-e "/etc/hosts.deny文件的内容:\n"$hosts_deny
else
	echo "未配置/etc/hosts.deny文件，内容为空"
fi
echo

echo ">>>>>>>>>>>>>>>>> [防火墙规则查看:] <<<<<<<<<<<<<<<<<"
echo `ufw status`
echo
echo -e "查看所有开放的端口：\n"`netstat -aptn`

# ************************************ 入侵防范e） ************************************
echo "************************************ 安全漏洞管理 ************************************"
echo
echo ">>>>>>>>>>>>>>>>> [查看系统版本信息是否存在安全漏洞:] <<<<<<<<<<<<<<<<<"
echo -e " 系统版本:\t "`lsb_release -d`
echo -e " 内核版本:\t "`uname -a`
echo

echo ">>>>>>>>>>>>>>>>> [查看系统安装补丁情况：] <<<<<<<<<<<<<<<<<"
patchinfo=`dpkg -l | grep '\bpatch\b'`
if [ -n $patchinfo ]; then
	echo  -e "存在以下已安装的补丁：\n"$patchinfo
else
	echo "未存在补丁安装包"
fi
echo
echo
# ************************************ 入侵防范f） ************************************
echo "************************************ 入侵防范措施 ************************************"
echo
echo ">>>>>>>>>>>>>>>>> [查看是否具备入侵检测措施：] <<<<<<<<<<<<<<<<<"
echo -e "访谈管理员是否存在入侵检测措施："
echo "如CrowdStrike Falcon、EventLog Analyzer、OSSEC、Sagan、Security Onion（Linux）、AIDE、Samhain、Fail2Ban等"
echo
echo




# ************************************ 恶意代码防范 ************************************
echo "************************************ 恶意代码防范 ************************************"
echo
echo ">>>>>>>>>>>>>>>>> [查看是否安装了恶意代码防范措施:] <<<<<<<<<<<<<<<<<"
clam=`clamscan -V 2>/dev/null`
if [[ -n $clam ]];then
	echo -e "已安装clamav，其版本号为："$clam
else
	echo "未安装clamav"
fi
echo


echo ">>>>>>>>>>>>>>>>> [查看是否配置了计划任务定期查杀病毒：] <<<<<<<<<<<<<<<<<"
clam_crontab=`crontab -l | grep clamscan`
if [[ -n $clam_crontab ]];then
  echo -e "已配置clamav定时计划任务进行查杀：\n"$clam_crontab
else
  echo -e "未配置clamav定时计划任务进行查杀"
 fi
 echo
freshclam=`crontab -l | grep freshclam`
if [[ -n $freshclam ]];then
    echo -e "已计划定时更新clamav病毒库：\n"$freshclam
else
	echo -e "未计划定时更新clamav病毒库"
  fi

echo
echo -e "访谈管理员是否存在其他恶意代码防范措施："
echo "如safedog、kingsoft等"
echo
echo

echo
# ************************************ 数据安全 ************************************
echo "************************************ 重要数据的完整性和重要数据的备份恢复 ************************************"
echo 
# 查看/var/spool/cron文件下是否具备其他的计划任务
echo ">>>>>>>>>>>>>>>>> [查看/var/spool/cron/目录下是否存在其他crontab文件:] <<<<<<<<<<<<<<<<<"
echo
cron=`ls /var/spool/cron`
if [[ -n $cron ]];then
	echo -e "当前存在其他的定时计划任务：\n"$cron
else
	echo "该目录为空，无其他人员的定时计划任务"
fi
echo
# 获取用户输入的安全管理员账户名
echo ">>>>>>>>>>>>>>>>> [查看其他管理员的crontab文件:] <<<<<<<<<<<<<<<<<"
read -p  "请输入其他管理员账户名：" users
echo
# 执行runuser命令
echo -e "查看其他管理员$users创建的定时计划任务内容:"
runuser -l $users -c " crontab -l |grep -v '^#'"
echo
echo


# ************************************ 数据安全 ************************************
echo "************************************ 剩余信息保护 ************************************"
echo
echo ">>>>>>>>>>>>>>>>> [查看是否留存历史记录：] <<<<<<<<<<<<<<<<<"
echo
bash_history=`head -n 10 ~/.bash_history`
echo 
echo -e "查看是否保存历史记录信息：\n"$bash_history
echo
echo
echo ">>>>>>>>>>>>>>>>> [查看/etc/profile文件下的HISTSIZE和HISTFILESIZE的配置值：] <<<<<<<<<<<<<<<<<"
hist=`grep 'HISTSIZE\|HISTFILESIZE' /etc/profile`
if [[ -n $hist ]];then
	echo -e "查看保存历史记录信息记录总数：\n"$hist
else
	echo "未设置保存历史记录数"
echo
echo ">>>>>>>>>>>>>>>>> [查看~/.bashrc文件下的HISTSIZE和HISTFILESIZE的配置值：] <<<<<<<<<<<<<<<<<"
username=$(whoami)
echo "当前登录的用户名为："$username
fi
## hist_user=`grep 'HISTSIZE\|HISTFILESIZE' /$username/.bashrc`
if [[ -n $hist ]];then
	echo -e "查看保存历史记录信息记录总数：\n"grep 'HISTSIZE\|HISTFILESIZE' /$username/.bashrc
else
	echo "未设置保存历史记录数"
echo
fi
}


#suse(){

#}


###################################################### 数据库 #############################################################


##判断数据库是否使用SSL登录的函数
# 引用MariaDB数据库的sql文件
Is_SSL(){
	if [[ $isSSL = "yes" ]] ||  [[ $isSSL = "y" ]];then
			read -p "请输入您的数据库账户名：" username
		read -p "请输入您的数据库目标地址：" ip_addr
		read -sp "请输入您的数据库口令（口令已隐藏）：" password 
		echo -e "可能强制使用SSL登录，请根据下方提示输入账户口令及相应的证书文件信息：\n"
		read -p  "请输入您的ca证书：" ca_cert
		read -p  "请输入您的客户端证书cert：" client_cert
		read -p  "请输入您的客户端密钥key：" client_key
		mysql -h$ip_addr -u$username -p$password --ssl-ca=$ca_cert --ssl-cert=$client_cert --ssl-key=$client_key -e"source /root/Desktop/mariadb10_11.sql"
		echo
		break;
	elif [[ $isSSL = "no" ]] ||  [[ $isSSL = "n" ]];then 
		read -p "请输入您的数据库账户名：" username
		read -p "请输入您的数据库目标地址：" ip_addr
		read -sp "请输入您的数据库口令（口令已隐藏）：" password
		mysql -h$ip_addr -u$username -p$password -e"source /root/Desktop/mariadb10_11.sql"	
		echo
		break;
	fi
}
##若输入其他不相干的字符串，二次判断是否使用SSL的函数
Twice_Is_SSL(){
	read -p $'请您根据实际情况输入: [yes/no]\n' isSSL           #字符串必须使用单引号
Is_SSL
}

#脚本调用的MariaDB的主函数
mariadb_10.11(){
	IFS=''
	read -p $'数据库是否强制使用SSL进行登录？[yes/no]\n' isSSL  ##达到换行的效果 ##字符串必须使用单引号
	
	# 重定向
	read -p "请问是否需要将测评结果输出到/var/exam/db.txt？[yes/no]" redirects
if [[ $redirects = "yes" ]] ||  [[ $redirects = "y" ]];then
	mkdir -p /var/exam/
	touch /var/exam/mariadb10_11-$(date +%Y-%m-%d\ %H:%M:%S).txt
	redirects_catalogs="/var/exam/mariadb10_11-$(date +%Y-%m-%d\ %H:%M:%S).txt"
	exec >"$redirects_catalogs"
	fi

	while [[ $isSSL = "yes" ]] ||  [[ $isSSL = "y" ]] || [[ $isSSL = "no" ]] ||  [[ $isSSL = "n" ]] ;do
	Is_SSL
	echo
	echo
	echo "##################################"
	echo -e "#以下是MariaDB数据库的基线检查：#"
	echo "##################################"
	echo

	done

	until [[ $isSSL = "yes" ]] ||  [[ $isSSL = "y" ]] || [[ $isSSL = "no" ]] ||  [[ $isSSL = "n" ]] ;do
	Twice_Is_SSL
	echo
	echo "##################################"
	echo -e "#以下是MariaDB数据库的基线检查：#"
	echo "##################################"
	echo
	#break;
	done



# 再查看操作系统下的配置文件
IFS=''
echo 
echo -e "查看MariaDB数据库的配置文件：\n"`cat /etc/my.cnf`
echo
echo "MariaDB数据库检查完毕"
}


#################################################### 获取型号和版本号 #################################################
# 获取操作系统和版本号
os="$2"
os_version="$3"

# 根据操作系统和版本号输出对应的函数
case "$os" in
    centos)
        case "$os_version" in
            7)
                echo "centos7"
                ;;
            8)
                centos8
                ;;
        esac
        ;;
    ubuntu)
        case "$os_version" in
            16.04)
                echo "Ubuntu_16.04"
                ;;
            18.04)
                echo "Ubuntu_18.04"
                ;;
			20.04)
                Ubuntu20.04
                ;;
        esac
esac

# 获取数据库厂商和版本号
db_name="$2"
db_version="$3"

# 根据型号和版本输出对应的函数
case "$db_name" in
    mysql)
        case "$db_version" in
            6)
                echo "mysql6"
                ;;
            7)
                echo "mysql7"
                ;;
			8)
                echo "mysql8"
                ;;
        esac
        ;;
    mariadb)
        case "$db_version" in
            10.11)
                mariadb_10.11
                ;;
            10)
                echo "mariadb_10"
                ;;
        esac
        ;;
    oracle)
        case "$db_version" in
            11g)
                echo "oracle_11g"
                ;;
            19c)
                echo "oracle_19c"
                ;;
        esac
esac

######################################################## SSH ##############################################################

# ssh函数  #####安装sshpass包
install_sshpass(){
wget http://sourceforge.net/projects/sshpass/files/latest/download -O sshpass.tar.gz
chmod 777 sshpass.tar.gz
tar -zxvf sshpass.tar.gz
cd sshpass-1.10
./configure
make
make install
pwd
cd ..
pwd
echo "安装成功！"
echo 
}

progress_bar(){  #定义进度条
i=0    #记录循环的次数
j='#'  
k=('|' '\' '-' '/')
l=0    #记录当前进度条样式的索引
while [ $i -le 25 ]
do
    printf "正在检测是否安装SSHPASS:[%-25s][%d%%][%c]\r" $j $(($i*4)) ${k[$l]}   #\r很重要
    j+='#'
    let i++   #let只能用于赋值计算，不能直接输出来，不可以条件判断
    let l=i%4
    sleep 0.05
done
echo
}

Is_sshpass(){
judge_sshpass=`sshpass -V 2>/dev/null`
progress_bar
echo
if [[ -n $judge_sshpass ]];then
	echo -e "检测到已安装sshpass"$judge_sshpass
	echo
else
	echo -e "###（仅在远程登录管理时需要）###"
	read -p "未检测到sshpass，是否安装sshpass?[yes/no]：" is_sshpass_install
		if [[ $is_sshpass_install = "yes" ]] ||  [[ $is_sshpass_install = "y" ]];then
		install_sshpass
	else
		echo "您已取消安装sshpass，无法正确进行ssh远程连接，请确保在本地使用此脚本！"
		echo
	fi
fi
}

ssh_login(){
Is_sshpass
file_name=`basename $0`
echo $file_name
read -p "请输入目标服务器的IP地址：" ssh_ipaddr
read -p "请输入目标服务器的账户名：" ssh_username
read -sp $'请输入登录目标服务器的账户名的口令(口令已隐藏)：\n' ssh_password
read -p "请输入您想要测评的操作系统或数据库 [-os/-db]:" check_selection
read -p "请输入您想要测评的版本[centos/ubuntu/mariadb]:" check_brand
read -p "请输入您想要测评的版本号[8/20.04/10.11]：" check_version
sshpass -p $ssh_password ssh -o StrictHostKeyChecking=no $ssh_username@$ssh_ipaddr "bash -s" -- < $file_name "$check_selection" "$check_brand" "$check_version"    ##注意双破折号-- （表示命令选项的结束）和参数周围的引号。
echo
echo -e "已成功执行脚本，若您选择重定向，请cat /var/exam/exam.txt下查看执行结果"
}


######################################################## 说明指令 #########################################################
# --help的说明
if [[ $1 = "--help" ]] || [[ $1 = "-h" ]];then
    echo -e "\033[31m（必读）使用手册:\033[0m"
    echo -e "\033[32m1、运行脚本文件时，在脚本文件后加上相关指令[-s/-ssh/-os/-db]\033[0m"
	echo -e "\033[32m2、根据Linux操作系统版本，命令如：-os cenotos 8\033[0m"
	echo -e "\033[32m3、根据数据库版本，命令如：-db mariadb 10.11\033[0m"
	echo -e "\033[32m4、若需要ssh远程登录连接，命令如：-ssh\033[0m"
	echo -e "\033[32m5、可自行选择是否将检测结果重定向到指定文件/var/exam/*.txt\033[0m"
	echo -e "\033[32m6、执行bash -s可直接输入1，2，3，4，5进行对应测评对象的测评\033[0m"
	echo -e "\033[32m注：a.目前仅存在centos8.x和mariadb10.11版本的基线检查功能 \033[0m"
	echo -e "\033[32m    b.若无法执行脚本文件，请查看是否授予权限,执行chmod 755 Linux-0.9.7.sh \033[0m"
    exit 0
fi

# -os和-db的说明
while [[ ! -n $1 ]];do
	echo "请参照上方提示输入相关命令，如'-os 或 -db'"
	break
done
if [[ $1 = "-os" ]] && [[ -z $2 ]];then
		echo "请输入Linux版本,如centos、ubuntu"
	elif [[ $1 = "--database" ]] || [[ $1 = "-db" ]] && [[ -z $2 ]];then
		echo "请输入数据库厂商以及版本号"
fi	

if [[ -n $2 ]] && [[ -z $3 ]];then
	echo "请输入$2的版本号" 
	elif [[ $2 = "centos" ]] || [[ $2 = "ubuntu" ]] && [[ -z $3 ]];then
		echo -e "请输入$2操作系统版本，目前仅支持centos8、ubuntu20操作系统"
	elif [[ $2 = "mysql" ]] || [[ $2 = "mariadb" ]] || [[ $2 = "oracle" ]] && [[ -z $3 ]];then
		echo -e "请输入$2数据库版本号，目前仅支持mariadb10.11"
fi



# -ssh的说明
if [[ $1 = "-ssh" ]] ;then
     ssh_login
fi


## sample实例化的说明
if [[ $1 = "--sample" ]] || [[ $1 = "-s" ]];then
    echo -e "目前支持的测评对象快速实例:\n"
    echo -e "\033[32m[1]\033[0m  \033[31m运行CentOS 8 \033[0m"
	echo -e "\033[32m[2]\033[0m  \033[31m运行Ubuntu 20.04\033[0m"
	echo -e "\033[32m[3]\033[0m  \033[31m运行MariaDB 10.11\033[0m"
	echo
#进行测评对象实例化
read -p "输入您想要测评的实例[1/2/3]：" sample_number 
case "$sample_number" in
    1)
		centos8
    ;;
    2)
        Ubuntu20.04
    ;;
	3)
		mariadb_10.11
	;;
esac
fi

if [[ $1 = "--cent" ]] || [[ $1 = "-c" ]];then
	centos8
fi