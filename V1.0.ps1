<# 
文件名:	        windows.ps1
描述: 		    安全基线检查-Windows 2022 & Windows 2012 server R2
使用:			.\windows.ps1
作者：          标准化室-zmt@gmail.com  
开发版本：      v0.1.1
开发时间：      2023.12.22
更新说明：      1）使用带BOM的UTF-8的编码，可以解决中文字符乱码的问题-12.25
开发计划：     
		2023.12.22
			   1）具备初始框架
               2）具备文件说明
               3）编写身份鉴别a）
			   4）具备截图函数-2024.2.1 (添加‘Add-Type -AssemblyName System.Windows.Forms’语句可以进行截图)
			   5）硬编码添加-h的帮助信息
			   6）添加ip地址信息，添加secedit的导出路径和文件设置
			   7）使用函数.可以进行配置文件的单独对比与调用——2024.4.24
			   8）使用各种颜色进行区分，更好看一点
		2024.4.25	   
			   1）访问控制完成
			   2）完成安全审计
		2024.4.28
			   1）添加是否管理员的判断
	    2024.5.7
			   1）添加作用域判定
			   2）完成脚本的检查编写
			   3）添加远程登录执行本地脚本的代码
		2024.5.8
				1）实现本地和远程脚本可分开执行
		2024.9.6
				1）新增部分空白输出项
				2）更新部分乱输出项
版权归属：©
#>
######################################################## 说明指令 #########################################################
# --help的说明
function Show-Help {  
    Write-Host -ForegroundColor Red "（必读）使用手册:"  
    Write-Host -ForegroundColor Green "1、检测策略文件会导出到该脚本所在的目录中"  
	Write-Host -ForegroundColor Green "2、可以选择进行本地或远程执行该脚本，且自动检测是否使用管理员权限打开powershell"  
    Write-Host -ForegroundColor Green "3、远程登录时若服务器为域控制器，账户填写格式：域名\用户名，比如：abc.com\Administrator"  
    Write-Host -ForegroundColor Green "4、有部分黄色区域仍需要进行二次判定，请自行进行鉴别"
	Write-Host -ForegroundColor Green "5、会有共享账户导出到目录中，请自行进行二次鉴别"
}  
  
if ($args[0] -eq "-h") {  
    Show-Help 
	exit 0
}

function Show-color {  
    Write-Host -ForegroundColor Green "绿色表示该测评项为符合"  
    Write-Host -ForegroundColor red "红色代表该测评项为不符合"  
    Write-Host -ForegroundColor yellow "黄色代表该测评项需进行二次测评"  
    Write-Host -ForegroundColor DarkGray "灰色代表相关说明项"  
    Write-Host -ForegroundColor cyan "其他的颜色为区分、分隔测评项"  
}  
  
if ($args[0] -eq "-c") {  
    Show-color 
	exit 0
}

Write-Host -ForegroundColor Cyan "
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
              \V/                                                                        V1.0
"

Write-Host  ">############################################################################################<" -ForegroundColor yellow
Write-Host  "--help  -h                                                     ##查看帮助" -ForegroundColor yellow
Write-Host  "--color -c                                                     ##查看字体颜色说明" -ForegroundColor yellow
Write-Host  "--remote -r                                                    ##进行远程连接Windows服务器并执行脚本" -ForegroundColor yellow
Write-Host  "--local -l                                                     ##进行本地执行脚本" -ForegroundColor yellow
Write-Host  ">############################################################################################<" -ForegroundColor yellow
Write-Host ""
# exit

#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>windows server 2022主函数<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<#

function Main{
########################################### Information ################################################################################################
Write-Host "************************************ IP地址 ************************************"
$ipAddress = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex (Get-NetAdapter | Where-Object Status -eq 'Up').IfIndex).IPAddress   #获取当前系统上所有活动网络接口的IPv4地址。
(Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex (Get-NetAdapter | Where-Object Status -eq 'Up').IfIndex).IPAddress

########################################### 导出本地组策略配置 ################################################################################################
# 创建导出的文件名（使用.txt扩展名）
$path = (Get-Location).Path  
New-Item -Path "$path\screenshot" -ItemType Directory #创建截图所需的文件夹
$fileName = "$ipAddress~config.txt"
$combo_name = "$path\$fileName"
Write-Host ""
Write-Host "将组策略导出到当前执行脚本目录中($path)"# 输入实际导出路径
secedit /export /cfg $fileName /quiet

<#else {( $is_export_directory -eq "no" -or $is_export_directory -eq "n" )
	$userInput = Read-Host "请输入要导出的目录位置"
	Write-Host "组策略导出到$userInput"
	$diy_fileName = "$userInput\$fileName"
	secedit /export /cfg $diy_fileName /quiet
}#>
<# 判断比对本地组策略配置
########################################### 判断比对本地组策略配置 ################################################################################################
#判断文件的导出目录
if ( $is_export_directory -eq "yes" -or $is_export_directory -eq "y" ){
	$policyContent = Get-Content -Path $fileName
}else {( $is_export_directory -eq "no" -or $is_export_directory -eq "n" )
	$policyContent = Get-Content -Path $diy_fileName
}

# 创建一个哈希表来存储期望的值
$expectedPolicies = @{
    "MinimumPasswordAge" = @{value=30;msg="密码最短留存期"}
    "MaximumPasswordAge" = @{value=90;msg="密码最长留存期"}
    "PasswordComplexity" = @{value=1;msg="密码必须符合复杂性要求策略"}
	"MinimumPasswordLength" = @{value=8;msg="密码长度最小值"}
	"PasswordHistorySize" = @{value=3;msg="强制密码历史个记住的密码"}
	"LockoutBadCount" = @{value=6;msg="账户登录失败锁定阈值次数"}
	"ResetLockoutCount" = @{value=15;msg="账户锁定时间(分钟)"}
	"LockoutDuration" = @{value=15;msg="复位账户锁定计数器时间(分钟)"}
	"RequireLogonToChangePassword" = @{value=0;msg="下次登录必须更改密码"}
	"ForceLogoffWhenHourExpire" = @{value=0;msg="强制过期"}
	"NewAdministratorName" = @{value='"Administrator"';msg="当前系统默认管理账号登陆名称策略"}
	"NewGuestName" = @{value='"Guest"';msg="当前系统默认来宾用户登陆名称策略"}
	"EnableAdminAccount" = @{value=1;msg="管理员账户停用与启用策略"}
	"EnableGuestAccount" = @{value=0;msg="来宾账户停用与启用策略"}
	"AuditSystemEvents" = 0
	"AuditLogonEvents" = 0
	"AuditObjectAccess" = 0
	"AuditPrivilegeUse" = 0
	"AuditPolicyChange" = 0
	"AuditAccountManage" = 0
	"AuditProcessTracking" = 0
	"AuditDSAccess" = 0
	"AuditAccountLogon" = 0
    # ... 添加更多期望的策略和值
}

# 遍历每一行并检查是否与期望值匹配
foreach ($line in $policyContent) {
    $parts = $line -split "=" #将每一行按等号（=）分割成两部分，并存储在 $parts 数组中。
    if ($parts.Length -eq 2) {   #确保分割后的部分有两个（即策略名称和策略值）
        $policyName =$parts[0].Trim()  #去除分割后字符串两端的空白字符，并分别赋值给 $policyName 和 $policyValue。
        $policyValue =$parts[1].Trim()
        # 检查是否存在期望值，并比较
        if ($expectedPolicies.ContainsKey($policyName)) { 
            $expectedValue = $expectedPolicies[$policyName] # 检查哈希表 $expectedPolicies 中是否包含当前策略名称。
            if ($policyValue -eq $expectedValue.value) { # 如果包含，则获取期望的值 $expectedValue，并与实际的策略值 $policyValue 进行比较
                Write-Host "策略'$($expectedValue.msg)'的策略值为'$($expectedValue.value)'，判定为符合" -ForegroundColor Green
            } else {
                Write-Host "策略'$($expectedValue.msg)'与期望策略值不一致。期望值为'$($expectedValue.value)',实际值:'$policyValue'" -ForegroundColor Red  #需要双重调用$($
            }
		}
	}
}
#>
########################################### 函数模块化 #############################################
function Get-PolicyContent {
    param (
        [string]$fileName
    )
    $policyContent = Get-Content $fileName
    return $policyContent
}

function Check-PolicyCompliance {
    param (
        [string]$path,
        [hashtable]$expectedPolicies
    )

    # 定义文件名
    $fileName = "$ipAddress~config.txt"
    $combo_name = "$path\$fileName"

    # 获取策略内容
    $policyContent = Get-PolicyContent -fileName $combo_name

    # 遍历每一行并检查是否与期望值匹配
    foreach ($line in $policyContent) {
        $parts = $line -split "=" # 将每一行按等号（=）分割成两部分，并存储在 $parts 数组中。
        if ($parts.Length -eq 2) {   # 确保分割后的部分有两个（即策略名称和策略值）
            $policyName = $parts[0].Trim() # 去除分割后字符串两端的空白字符，并分别赋值给 $policyName 和 $policyValue。
            $policyValue = $parts[1].Trim()
            # 检查是否存在期望值，并比较
            if ($expectedPolicies.ContainsKey($policyName)) {
                $expectedValue = $expectedPolicies[$policyName]
                if ($policyValue -eq $expectedValue.value) {
                    Write-Host "策略'$($expectedValue.msg)'的策略值为'$($expectedValue.value)'，判定为符合" -ForegroundColor Green
                } else {
                    Write-Host "策略'$($expectedValue.msg)'与期望策略值不一致。期望值为'$($expectedValue.value)',实际值:'$policyValue'" -ForegroundColor Red
                }
            }
        }
    }
}
$path = (Get-Location).Path
function Put-PolicyCompliance {
    param (
        [string]$path,
        [hashtable]$expectedPolicies
    )

    # 定义文件名
    $fileName = "$ipAddress~config.txt"
    $combo_name = "$path\$fileName"

    # 获取策略内容
    $policyContent = Get-PolicyContent -fileName $combo_name

    # 遍历每一行并检查是否与期望值匹配
    foreach ($line in $policyContent) {
        $parts = $line -split "=" # 将每一行按等号（=）分割成两部分，并存储在 $parts 数组中。
        if ($parts.Length -eq 2) {   # 确保分割后的部分有两个（即策略名称和策略值）
            $policyName = $parts[0].Trim() # 去除分割后字符串两端的空白字符，并分别赋值给 $policyName 和 $policyValue。
            $policyValue = $parts[1].Trim()
            # 检查是否存在期望值，并比较
            if ($expectedPolicies.ContainsKey($policyName)) {
                $expectedValue = $expectedPolicies[$policyName]
                if ($policyValue -eq $expectedValue.value) {
                    Write-Host "策略'$($expectedValue.msg)'的值为'$($expectedValue.value)'" -ForegroundColor Yellow
                } else {
                    Write-Host "策略'$($expectedValue.msg)'与期望策略值不一致。期望值为'$($expectedValue.value)',实际值:'$policyValue'" -ForegroundColor Red
                }
            }
        }
    }
}

###########################################屏幕截图################################################
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.SendKeys]::SendWait("{PrtSc}")  
#$bitmap = [System.Windows.Forms.Clipboard]::GetImage()

function Get-ScreenCapture{
    param(
    [Switch]$OfWindow
    )


    begin {
        Add-Type -AssemblyName System.Drawing
        $jpegCodec = [Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() |
            Where-Object { $_.FormatDescription -eq "JPEG" }
    }
    process {
        Start-Sleep -Milliseconds 300
        if ($OfWindow) {
            [Windows.Forms.Sendkeys]::SendWait("%{PrtSc}")
        } else {
            [Windows.Forms.Sendkeys]::SendWait("{PrtSc}")
        }
        Start-Sleep -Milliseconds 300
        $bitmap = [Windows.Forms.Clipboard]::GetImage()
        $ep = New-Object Drawing.Imaging.EncoderParameters
        $ep.Param[0] = New-Object Drawing.Imaging.EncoderParameter ([System.Drawing.Imaging.Encoder]::Quality, [long]100)
        $screenCapturePathBase = "$pwd\screenshot\ScreenCapture"
        $c = 0
        while (Test-Path "${screenCapturePathBase}${c}.jpg") {
            $c++
        }
        $bitmap.Save("${screenCapturePathBase}${c}.jpg", $jpegCodec, $ep)
    }
}
Write-Host ""

############################################# 核查是否以管理员权限进行登录 ################################################################################################
$user = [Security.Principal.WindowsIdentity]::GetCurrent(); 
$is_administrator = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) 
if ($is_administrator){
	Write-Host "已通过管理员身份运行该脚本" -ForegroundColor Green
}else {
	Write-Host "未以管理员身份运行该脚本，正在退出" -ForegroundColor red
	Write-Host "请以管理员身份再次运行该脚本" -ForegroundColor red
    return
}
Write-Host ""

########################################### Information ################################################################################################
Write-Host "************************************ IP地址 ************************************"
$ipAddress = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex (Get-NetAdapter | Where-Object Status -eq 'Up').IfIndex).IPAddress   #获取当前系统上所有活动网络接口的IPv4地址。
(Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex (Get-NetAdapter | Where-Object Status -eq 'Up').IfIndex).IPAddress

#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>windows server 2022<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<#
###########################################身份鉴别################################################
Write-Host "************************************ 身份鉴别 ************************************" -BackgroundColor DarkCyan
Write-Host ""
Write-Host "------------------------------- a）身份鉴别措施 -------------------------------" -BackgroundColor Magenta
Write-Host ""
# 是否具备身份鉴别措施
Write-Host ">>>>>>>>>>>>>>>>>>>> [是否存在自动登录鉴别措施:] <<<<<<<<<<<<<<<<<<<<"
$isChecked = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device').DevicePasswordLessBuildVersion  
if ($isChecked -eq 2) {  
    Write-Host "'DevicePasswordLessBuildVersion'键的值为2,(默认值为“2”,表示未开启选项框)"  -ForegroundColor Green
} else {
    Write-Host "'DevicePasswordLessBuildVersion'键的值为0,表示开启了选项框，需要进一步查看"  -ForegroundColor Yellow
}
Write-Host ""

# 选项框截图
Write-Host '查看“要使用本计算机，用户必须输入用户名和密码”的选项框，并进行截图（已保存在：该文件目录\screenshot\ScreenCapture）：' -ForegroundColor Yellow
Netplwiz.exe
Start-Sleep -Milliseconds 300
Get-ScreenCapture
Write-Host ""

$keyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$keys = @("DefaultUserName", "DefaultPassword", "AutoAdminLogon")

foreach ($key in $keys) {
    if (Test-Path $keyPath\$key) {
        $value = Get-ItemProperty $keyPath\$key
        Write-Host "$key 存在, 值为 $value" -ForegroundColor Red #第二种写法$value = (Get-ItemProperty -Path $keyPath\$key).$key则会在尝试获取注册表的值之前，先检查这个键是否存在
    } else {
        Write-Host "$key 不存在" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host '若同时配置“DevicePasswordLessBuildVersion”条目为0,“AutoAdminLogon”条目为1,会开启自动登录措施'
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [远程登录时是否采用身份鉴别机制:] <<<<<<<<<<<<<<<<<<<<"
$isChecked = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').LocalAccountTokenFilterPolicy
if ($isChecked -eq 1) {  
    Write-Host "'账户：使用空密码的本地帐户只允许进行控制台登录'选项已启用"  -ForegroundColor Green
} else {
    Write-Host "'账户：使用空密码的本地帐户只允许进行控制台登录'选项未启用"  -ForegroundColor Red
}

Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [策略'始终在连接时提示输入密码':] <<<<<<<<<<<<<<<<<<<<"
$isChecked = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services').fPromptForPassword
if ($isChecked -eq 1) {  
    Write-Host "'始终在连接时提示输入密码'选项已启用" -ForegroundColor Green
} else {
    Write-Host "'始终在连接时提示输入密码'选项未启用" -ForegroundColor Red
}
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [远程登录时策略'允许我保存凭证':] <<<<<<<<<<<<<<<<<<<<"
$isChecked = (Get-ItemProperty -Path 'HKLM:\SYSTEM\ControlSet001\Control\Terminal Server\WinStations\RDP-Tcp').fPromptForPassword
if ($isChecked -eq 1) {  
    Write-Host "将始终提示用户输入口令，即使密码是从以前的连接中保存的"  -ForegroundColor Green
} else {
    Write-Host "可以使用之前保存的口令"  -ForegroundColor Red
}
Write-Host ""

###########################################身份标识唯一性################################################
Write-Host ""
Write-Host "------------------------------- 身份标识唯一性 -------------------------------"
Write-Host ">>>>>>>>>>>>>>>>>>>> [核查账户列表，并访谈是否存在多人共用账户口令的情况] <<<<<<<<<<<<<<<<<<<<"
wmic useraccount get name,sid
Write-Host ""

###########################################口令复杂度################################################
Write-Host ""
Write-Host "------------------------------- 口令复杂度 -------------------------------"
Write-Host ">>>>>>>>>>>>>>>>>>>> [查询口令最小长度] <<<<<<<<<<<<<<<<<<<<"
$expectedPolicies = @{
    "MinimumPasswordLength" = @{value=8;msg="密码长度最小值"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""


Write-Host ">>>>>>>>>>>>>>>>>>>> [是否开启复杂度设置] <<<<<<<<<<<<<<<<<<<<"
$expectedPolicies = @{
    "PasswordComplexity" = @{value=1;msg="密码必须符合复杂性要求策略"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [密码最长留存期] <<<<<<<<<<<<<<<<<<<<"
$expectedPolicies = @{
    "MaximumPasswordAge" = @{value=90;msg="密码最长留存期"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

###########################################登录失败处理措施################################################
Write-Host ""
Write-Host "------------------------------- b）登录失败处理 -------------------------------" -BackgroundColor Magenta
Write-Host ">>>>>>>>>>>>>>>>>>>> [登录失败尝试次数] <<<<<<<<<<<<<<<<<<<<"
$expectedPolicies = @{
    "LockoutBadCount" = @{value=5;msg="账户登录失败锁定阈值次数"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [登录失败锁定时间] <<<<<<<<<<<<<<<<<<<<"
$expectedPolicies = @{
	"ResetLockoutCount" = @{value=15;msg="账户锁定时间(分钟)"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [屏幕保护程序是否启用] <<<<<<<<<<<<<<<<<<<<"
$isChecked = (Get-ItemProperty -Path 'HKCU:\Control Panel\Desktop').ScreenSaveActive
if ($isChecked -eq 1) {  
    Write-Host "已启用屏幕保护程序"  -ForegroundColor Green
} else {
    Write-Host "未启用屏幕保护程序"  -ForegroundColor Red
}
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [屏幕保护程序是否需要密码解锁] <<<<<<<<<<<<<<<<<<<<"
$isChecked_save = (Get-ItemProperty -Path 'HKCU:\Control Panel\Desktop').ScreenSaverIsSecure
if ($isChecked_save -eq 1) {  
    Write-Host "需要密码进行解锁"  -ForegroundColor Green
} else {
    Write-Host "不需要密码就可以解锁"  -ForegroundColor Red
}
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [屏幕保护程序设置超时时间] <<<<<<<<<<<<<<<<<<<<"
$isChecked_timeout = (Get-ItemProperty -Path 'HKCU:\Control Panel\Desktop').ScreenSaveTimeOut 
if($isChecked_timeout -eq 0){
	Write-Host "未设置屏幕保护程序超时时间" -ForegroundColor red
}elseif($isChecked_timeout -eq $null){
	Write-Host "未设置屏幕保护程序超时时间" -ForegroundColor red
}
elseif ($isChecked_timeout -le 900) {  
    Write-Host "屏幕保护程序超时时间合理，设置为:"$isChecked_timeout -NoNewline -ForegroundColor Green
	Write-Host "（秒）" -ForegroundColor Green
} else {
    Write-Host "屏幕保护程序超时时间过大，设置为:"$isChecked_timeout -NoNewline -ForegroundColor Red
	Write-Host "（秒）" -ForegroundColor Red
}
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [组策略中的“交互式登录：计算机不活动限制”值] <<<<<<<<<<<<<<<<<<<<"
$is_Security_Checked_timeout = (Get-ItemProperty -Path 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').InactivityTimeoutSecs 
#$decimal = [int]::Parse($is_Security_Checked_timeout, 16)  #转化16进制为10进制，但是默认就是输出十进制，白干活
if ($is_Security_Checked_timeout -eq 0) {  
    Write-Host "未设置用户不活动超时时间" -ForegroundColor Red
} elseif ($is_Security_Checked_timeout -eq $null) {  
    Write-Host "未设置用户不活动超时时间" -ForegroundColor Red
} elseif($is_Security_Checked_timeout -le 900){
	Write-Host "用户不活动超时时间合理，设置为:"$is_Security_Checked_timeout -NoNewline -ForegroundColor Green
	Write-Host "（秒）" -ForegroundColor Green
}else{
	Write-Host "用户不活动超时时间过大，设置为:"$is_Security_Checked_timeout -NoNewline -ForegroundColor Red
	Write-Host "（秒）" -ForegroundColor Red
}
Write-Host ""


Write-Host ">>>>>>>>>>>>>>>>>>>> [远程登录空闲后超时时间] <<<<<<<<<<<<<<<<<<<<"
$isChecked_remote_timeout = (Get-ItemProperty -Path 'HKLM:SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services').MaxIdleTime
$result=$isChecked_remote_timeout/1000
if ($result -eq 0) {  
	Write-Host "未设置远程登录空闲后超时时间" -ForegroundColor Red
} elseif($result -le 900){
    Write-Host "远程登录空闲后超时时间合理，设置为:"$result -NoNewline -ForegroundColor Green
	Write-Host "（秒）" -ForegroundColor Green
}else{
    Write-Host "远程登录空闲后超时时间不合理，设置为:"$result -NoNewline -ForegroundColor Red
	Write-Host "（秒）" -ForegroundColor Red
}
Write-Host ""

###########################################远程管理防窃听################################################
Write-Host ""
Write-Host "------------------------------- c）远程管理防窃听 -------------------------------" -BackgroundColor Magenta
Write-Host ">>>>>>>>>>>>>>>>>>>> [远程桌面登录服务使用的协议] <<<<<<<<<<<<<<<<<<<<"
$isChecked_remote = (Get-ItemProperty -Path 'HKLM:SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services').SecurityLayer
if ($isChecked_remote -eq 0) {  
    Write-Host "使用RDP进行身份验证"  -ForegroundColor yellow
} elseif ($isChecked_remote -eq 2) {
    Write-Host "使用TLS协议进行身份验证" -ForegroundColor Yellow
 }else{
	 Write-Host "未配置远程管理防窃听措施" -ForegroundColor red
 }
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [远程客户端连接加密级别] <<<<<<<<<<<<<<<<<<<<"
$isChecked_remote = (Get-ItemProperty -Path 'HKLM:SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services').MinEncryptionLevel
if ($isChecked_remote -eq 3) {  
    Write-Host "加密级别为高级别"  -ForegroundColor Green
} else {
    Write-Host "加密级别未使用高级别" -ForegroundColor Red
}
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [默认的远程客户端端口是否为3389] <<<<<<<<<<<<<<<<<<<<"
$RDP1 = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\').PortNumber
$RDP2 = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\Tds\tcp\').PortNumber
  if ( $RDP1 -eq $RDP2 -and $RDP2 -eq "3389") {
	Write-Host "默认的远程桌面端口为3389"  -ForegroundColor Yellow
  } else {
    Write-Host "默认的远程桌面端口已被修改为$($RDP1)"  -ForegroundColor Yellow
  }
###########################################访问控制################################################
Write-Host "************************************ 访问控制 ************************************" -BackgroundColor DarkCyan
Write-Host ""
Write-Host "------------------------------- a）账户分配、权限分配、权限限制 -------------------------------" -BackgroundColor Magenta
Write-Host ">>>>>>>>>>>>>>>>>>>> [用户信息表] <<<<<<<<<<<<<<<<<<<<"  -ForegroundColor yellow
Get-WmiObject -Class Win32_UserAccount  | Select-Object Disabled,Name,domain,FullName,AccountType,LocalAccount,Lockout,PasswordChangeable,PasswordRequired,SID,passwordexpires,Description
Write-Host ""


Write-Host ""
Write-Host ">>>>>>>>>>>>>>>>>>>> [用户权限分配与限制] <<<<<<<<<<<<<<<<<<<<"
$acl = icacls "C:\windows\system" | findstr "Guest"
                if ($acl -eq $null) {
                    Write-Host "不存在Guest账户对C:\windows\system文件夹等重要客体具备任何权限" -ForegroundColor Green
                } else {
                    Write-Host "存在Guest账户对C:\windows\system文件夹等重要客体具备权限。" -ForegroundColor Red
                }
Write-Host ""
$acl = icacls "C:\windows\system" | findstr "Everyone"
                if ($acl -eq $null) {
                    Write-Host "不存在Everyone账户对C:\windows\system文件夹等重要客体具备任何权限" -ForegroundColor Green
                } else {
                    Write-Host "存在Everyone账户对C:\windows\system文件夹等重要客体具备权限。" -ForegroundColor Red
                }
Write-Host ""


Write-Host "------------------------------- b）默认账户 -------------------------------" -BackgroundColor Magenta
Write-Host ">>>>>>>>>>>>>>>>>>>> [默认账户Administrator和Guest状态] <<<<<<<<<<<<<<<<<<<<"
$expectedPolicies = @{
    "NewAdministratorName" = @{value='"Administrator"';msg="当前系统默认管理账号登陆名称"}
}
Put-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

$expectedPolicies = @{
    "NewGuestName" = @{value='"Guest"';msg="当前系统默认来宾用户登陆名称"}
}
Put-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [查看默认账户的是否被禁用或重命名] <<<<<<<<<<<<<<<<<<<<" 
$users = Get-WmiObject -Class Win32_UserAccount -Filter "Name='Guest' OR Name='Administrator'" | Select-Object Disabled,Name,domain,FullName,Lockout
foreach ($user in $users) {
    if ($user.Disabled -eq $true) {
        Write-Host "$($user.Name)用户账户已被禁用。" -ForegroundColor green
    } else {
        Write-Host "$($user.Name)用户账户未被禁用。" -ForegroundColor red
    }
}
Write-Host ""
<# 查看默认账户的是否被禁用或重命名
Write-Host ">>>>>>>>>>>>>>>>>>>> [查看默认账户的是否被禁用或重命名] <<<<<<<<<<<<<<<<<<<<" 
$users = Get-WmiObject -Class Win32_UserAccount -Filter "Name='Administrator' OR Name='Guest'" | Select-Object Disabled,Name,domain,FullName,Lockout
foreach ($user in $users) {
    if ($user.Disabled -eq $true) {
        Write-Host "$($user.Name)用户账户已被禁用。" -ForegroundColor green
    } else {
        Write-Host "$($user.Name)用户账户未被禁用。" -ForegroundColor red
    }
}
#>
<# 用户信息表解析
Disabled: 这个属性表示账户是否被禁用。如果账户被禁用，这个属性通常为 True。

Name: 这是用户账户的登录名，也就是用户用来登录系统的名字。

Domain: 表示用户账户所属的域。如果是本地账户，通常显示为计算机的名称。

FullName: 用户的全名，通常比登录名更正式，包含了用户的名字和姓氏。

LocalAccount: 这个属性指示账户是本地账户还是域账户。对于本地账户，此属性通常为 True。

Lockout: 表示账户是否被锁定，通常是由于多次尝试使用错误的密码登录。

PasswordChangeable: 这个属性指示用户是否能够更改其密码。

PasswordRequired: 如果这个属性为 True，则表示用户必须有一个密码才能登录。

SID: 安全标识符（Security Identifier）是一个唯一的标识符，用来在安全上下文中唯一标识用户、用户组、计算机账户或其他安全主体。

PasswordExpires: 这个属性表示密码到期的日期，超过这个日期用户需要更改密码。

Description: 账户的描述，通常包含关于账户用途或用户的额外信息。

AccountType:账户的类型，如用户账户、管理员账户等。
	512 (0x0200) - 表示本地用户账户（Local User Account）。

	268435456 (0x10000000) - 表示域用户账户（Domain User Account）。

	536870912 (0x20000000) - 表示本地管理员账户（Local Administrator Account）。这个值通常与本地用户账户（512）组合使用，例如 512 + 536870912 = 536871424，表示该账户既是本地用户也是本地管理员。

	805306368 (0x30000000) - 表示域管理员账户（Domain Administrator Account）。这个值可能与域用户账户（268435456）组合使用，表示该账户既是域用户也是域管理员。
#>

Write-Host "------------------------------- c）多余、过期和共享的账户 -------------------------------" -BackgroundColor Magenta
Write-Host ">>>>>>>>>>>>>>>>>>>> [多余、过期的账户自行访谈核查] <<<<<<<<<<<<<<<<<<<<" -ForegroundColor Yellow
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [共享的账户] <<<<<<<<<<<<<<<<<<<<"
# 获取 ID 为 4648 的所有事件日志
$logName = 'Security'
$eventId = 4648
$local_path = (Get-Location).Path  
$share_Nickname = '共享账户.txt'
$share_name = "$local_path\$share_Nickname"
$events = Get-WinEvent -FilterHashtable @{LogName=$logName; ID=$eventId} | Format-List -Property TimeCreated, ProviderName, Message 
# 检查是否找到事件并显示它们
if ($events -eq $null) {
    Write-Host "未找到ID为$($eventId)的事件"  -ForegroundColor Red
} else {
	$events_save = Get-WinEvent -FilterHashtable @{LogName=$logName; ID=$eventId} | Format-List -Property TimeCreated, ProviderName, Message >>$share_name
    Write-Host "已找到ID为$($eventId)的事件，已存储到脚本自身所在目录的'共享账户.txt'中"  -ForegroundColor Yellow
}
Write-Host ""

Write-Host "------------------------------- d）最小权限 -------------------------------" -BackgroundColor Magenta
Write-Host ">>>>>>>>>>>>>>>>>>>> [用户角色划分最小权限] <<<<<<<<<<<<<<<<<<<<"
$groups = Get-LocalGroup

foreach ($group in $groups) {
  $members = Get-LocalGroupMember -Group $group.Name
  if($members -eq $null){
	  Write-Host "组名 - ($($group.Name)):"  -NoNewline
	  Write-Host "组内未存在用户" -ForegroundColor DarkGray
  }else{
	  Write-Host "组名 - ($($group.Name)):"
  }
  $members | Select-Object Name | Sort-Object Name | ForEach-Object {
    Write-Host "    组内用户：$($_.Name)" -ForegroundColor yellow
  }
}
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [组策略的用户权限分配] <<<<<<<<<<<<<<<<<<<<"
#  操作系统本地关机策略安全
$expectedPolicies = @{
    SeShutdownPrivilege = @{value='*S-1-5-32-544';msg="操作系统本地关机策略"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

#操作系统远程关机策略安全
$expectedPolicies = @{
    SeRemoteShutdownPrivilege = @{value='*S-1-5-32-544';msg="操作系统远程关机策略"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

#取得文件或其他对象的所有权限策略
$expectedPolicies = @{
    SeProfileSingleProcessPrivilege = @{value='*S-1-5-32-544';msg="取得文件或其他对象的所有权限策略"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

#从网络访问此计算机策略
$expectedPolicies = @{
    SeNetworkLogonRight = @{value='*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551';msg="从网络访问此计算机策略"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

Write-Host "SID对应表"  -ForegroundColor Yellow
Write-Host "S-1-5-32-544 Administrators（用户组）" -ForegroundColor DarkGray
Write-Host "S-1-5-32-545 Users（用户组）" -ForegroundColor DarkGray
Write-Host "S-1-5-32-546 Guest（用户组）" -ForegroundColor DarkGray
Write-Host "S-1-5-32-548 Account Operators（用户组）" -ForegroundColor DarkGray
Write-Host "S-1-5-32-549 Server Operators（用户组）" -ForegroundColor DarkGray
Write-Host "S-1-5-32-550 Print Operators（用户组）" -ForegroundColor DarkGray
Write-Host "S-1-5-32-551 Backup Operators（用户组）" -ForegroundColor DarkGray
Write-Host "S-1-5-32-573 Event Log Readers（用户组）" -ForegroundColor DarkGray
Write-Host "S-1-1-0 Everyone（用户）" -ForegroundColor DarkGray
Write-Host ""
<#
S-1-5-32-544	管理员	内置组。 初始安装操作系统后，组的唯一成员是 Administrator 帐户。 当计算机加入域时，“Domain Admins”组将添加到管理员组。 当服务器成为域控制器时，“Enterprise Admins”组也会被添加到管理员组。
S-1-5-32-545	使用者	內建群組。 在初始安裝作業系統之後，唯一成員是 Authenticated Users/Users 群組。
S-1-5-32-546	来宾	内置组。 默认情况下，唯一的成员是 Guest 帐户。 Guests 组允许偶尔或一次性用户以有限的权限登录计算机的内置 Guest 帐户。
S-1-5-32-547	超级用户	内置组。 默认情况下，该组没有任何成员。 超级用户可以创建本地用户和组；修改和删除已创建的帐户；以及从 Power Users、Users 和 Guests 组中删除用户。 超级用户也可以安装程序；创建、管理和删除本地打印机；以及创建和删除文件共享。
S-1-5-32-548	Account Operators	仅存在于域控制器上的内置组。 默认情况下，该组没有任何成员。 默认情况下，Account Operators 有权在 Active Directory 的所有容器和组织单位（内置容器和域控制器 OU 除外）中创建、修改和删除用户、组和计算机的帐户。 帐户操作员无权修改 Administrators 和 Domain Admins 组，也无权修改这些组的成员的帐户。
S-1-5-32-549	Server Operators	说明：仅存在于域控制器上的内置组。 默认情况下，该组没有任何成员。 Server Operators 可以交互式登录到服务器；创建和删除网络共享；启动和停止服务；备份和恢复文件；格式化计算机硬盘；然后关闭计算机。
S-1-5-32-550	打印操作员	仅存在于域控制器上的内置组。 默认情况下，唯一的成员是“Domain Users”组。 Print Operators 可以管理打印机和文档队列。
S-1-5-32-551	备份操作员	内置组。 默认情况下，该组没有任何成员。 Backup Operators 可以备份和还原计算机上的所有文件，而不管保护这些文件的权限如何。 Backup Operators 还可以登录到计算机并关闭计算机。
S-1-1-0	  		Everyone，包括所有用户的组。
#>

###########################################安全审计################################################
Write-Host "************************************ 安全审计 ************************************" -BackgroundColor DarkCyan
Write-Host ""
Write-Host "------------------------------- a）安全审计范围 -------------------------------" -BackgroundColor Magenta
Write-Host "Windows操作系统默认开启日志记录功能，且无法停用审计服务进程"  -ForegroundColor yellow
Write-Host ""
Write-Host ">>>>>>>>>>>>>>>>>>>> [本地策略的审计范围] <<<<<<<<<<<<<<<<<<<<" 
#审核策略更改 其中无审核为0，单开启成功为1，单开启失败为2，成功和失败都开启为3
$expectedPolicies = @{
   AuditPolicyChange = @{value=3;msg="审核策略更改"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

#审核登录事件
$expectedPolicies = @{
   AuditLogonEvents = @{value=3;msg="审核登录事件"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

#审核对象访问
$expectedPolicies = @{
   AuditObjectAccess = @{value=3;msg="审核对象访问"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

#审核过程追踪
$expectedPolicies = @{
   AuditProcessTracking = @{value=3;msg="审核过程追踪"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

#审核目录服务访问
$expectedPolicies = @{
   AuditDSAccess = @{value=3;msg="审核目录服务访问"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

#审核特权使用
$expectedPolicies = @{
   AuditPrivilegeUse = @{value=3;msg="审核特权使用"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

#审核系统事件
$expectedPolicies = @{
   AuditSystemEvents = @{value=3;msg="审核系统事件"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

#审核账户登录事件
$expectedPolicies = @{
   AuditAccountLogon = @{value=3;msg="审核账户登录事件"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

#审核账户管理
$expectedPolicies = @{
   AuditAccountManage = @{value=3;msg="审核账户管理"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""
Write-Host "****说明：无审核为0，单开启成功为1，单开启失败为2，成功和失败都开启为3****"  -ForegroundColor Darkgray
Write-Host ""


Write-Host "------------------------------- b）安全审计规则 -------------------------------" -BackgroundColor Magenta
Write-Host ""
Write-Host ">>>>>>>>>>>>>>>>>>>> [当前时间戳] <<<<<<<<<<<<<<<<<<<<" 
#获取系统时间
$Date = Get-Date 
Write-Host "$($Date)" -ForegroundColor Yellow
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [时钟同步（此项不做强制要求）] <<<<<<<<<<<<<<<<<<<<" 
#获取NTP时钟设备
$NTP = (Get-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer').Enabled
$NTP_addr = (Get-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Services\W32Time\Parameters').NtpServer
if ( $NTP -eq 1) {
    Write-Host "用户设置并启用了NTP服务器，查看设置NTP服务的地址为:$($NTP_addr)" -ForegroundColor Yellow
} else {
    Write-Host "用户设置未启用NTP服务器" -ForegroundColor Yellow
}
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [安全审计规则] <<<<<<<<<<<<<<<<<<<<" 
Write-Host "Windows操作系统默认规定审计信息规则，均包含日期和时间、主体标识、任务类型、事件ID、关键字、客体标识、结果等信息。"  -ForegroundColor Yellow


Write-Host "------------------------------- c）安全审计保护 -------------------------------" -BackgroundColor Magenta
Write-Host ""
#用户权限分配的管理审核和安全日志
Write-Host "*S-1-5-32-573为Event Log Readers用户组"
$expectedPolicies = @{
   SeSecurityPrivilege = @{value='*S-1-5-32-573';msg="管理审核和安全日志"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [日志最大大小] <<<<<<<<<<<<<<<<<<<<" 
$EventlogSystemMaxSize = (Get-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Services\Eventlog\System').MaxSize / 1024
if ($EventlogSystemMaxSize -le 1048576) {  
    Write-Host "系统日志查看器大小设置可能过小，设置为$($EventlogSystemMaxSize)(KB)"  -ForegroundColor Yellow 
} else {
    Write-Host "系统日志查看器大小设置合理，设置为$($EventlogSystemMaxSize)"  -ForegroundColor Yellow
}
Write-Host ""

$EventlogApplicationMaxSize = (Get-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Services\Eventlog\Application').MaxSize  / 1024
if ($EventlogApplicationMaxSize -le 1048576) {  
    Write-Host "应用程序日志查看器大小设置可能过小，设置为$($EventlogApplicationMaxSize)(KB)"  -ForegroundColor Yellow 
} else {
    Write-Host "应用程序日志查看器大小设置合理，设置为$($EventlogApplicationMaxSize)"  -ForegroundColor Yellow
}
Write-Host ""

$EventlogSecurityMaxSize = (Get-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Services\Eventlog\Security').MaxSize  / 1024
if ($EventlogSecurityMaxSize -le 1048576) {  
    Write-Host "安全日志查看器大小设置可能过小，设置为$($EventlogSecurityMaxSize)(KB)"  -ForegroundColor Yellow 
} else {
    Write-Host "安全日志查看器大小设置合理，设置为$($EventlogSecurityMaxSize)"  -ForegroundColor Yellow
}
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [达到事件日志最大大小时的操作] <<<<<<<<<<<<<<<<<<<<" 
$EventlogSystemMaxSize = (Get-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Services\Eventlog\System').AutoBackupLogFiles
if ($EventlogApplicationMaxSize -eq 1) {  
	Write-Host "系统日志满时将其存档，不覆盖事件"  -ForegroundColor Green 
} else {
    Write-Host "系统日志满时，按需要覆盖事件或不覆盖事件(手动清除日志)"  -ForegroundColor Yellow
}
Write-Host ""

$EventlogApplicationMaxSize = (Get-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Services\Eventlog\Application').AutoBackupLogFiles
if ($EventlogApplicationMaxSize -eq 1) {  
    Write-Host "应用程序日志满时将其存档，不覆盖事件"  -ForegroundColor Green 
} else {
    Write-Host "应用程序日志满时，按需要覆盖事件或不覆盖事件(手动清除日志)"  -ForegroundColor Yellow
}
Write-Host ""

$EventlogSecurityMaxSize = (Get-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Services\Eventlog\Security').AutoBackupLogFiles
if ($EventlogSecurityMaxSize -eq 1) {  
    Write-Host "安全日志满时将其存档，不覆盖事件"  -ForegroundColor Green 
} else {
    Write-Host "安全日志满时，按需要覆盖事件或不覆盖事件（手动清除日志）"  -ForegroundColor Yellow
}
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [审计备份] <<<<<<<<<<<<<<<<<<<<" 
Write-Host "未测试完" -ForegroundColor Yellow
<# 未测试完
Add-PSSnapin WindowsServerBackup
Get-WBSummary
Write-Host ""
#>


###########################################入侵防范################################################
Write-Host "************************************ 入侵防范 ************************************" -BackgroundColor DarkCyan
Write-Host ""
Write-Host "------------------------------- a）最小化原则 -------------------------------" -BackgroundColor Magenta
Write-Host ">>>>>>>>>>>>>>>>>>>> [最小化安装] <<<<<<<<<<<<<<<<<<<<" 
$MIN_install = Get-WmiObject -Class Win32_Product | Select-Object -Property Name,Version,IdentifyingNumber | Sort-Object Name | Out-String
Write-Host "$($MIN_install)" -ForegroundColor Yellow

Write-Host ""

Write-Host "------------------------------- b）最小化服务、默认共享、高危端口 -------------------------------" -BackgroundColor Magenta
Write-Host ">>>>>>>>>>>>>>>>>>>> [最小化服务] <<<<<<<<<<<<<<<<<<<<" 
$serviceNames = 'RemoteRegistry', 'Alerter','Bluetooth*', 'Clipbook','Computer Browser','Messenger','Routing and Remote Access','Simple Mail Trasfer Protocol','Simple Network、Management Protocol','Telnet','Print Spooler','Automatic Updates'
Get-Service -Name $serviceNames -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' } | Select-Object -Property Name, Status 
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [默认共享] <<<<<<<<<<<<<<<<<<<<" 
# - 检查关闭默认共享盘
$restrictanonymous = (Get-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Control\Lsa').restrictanonymous
if ($restrictanonymous -eq 1) {  
    Write-Host "系统网络基配核查-关闭默认共享盘策略"  -ForegroundColor Green 
} else {
    Write-Host "未关闭默认共享盘策略"  -ForegroundColor Red
}
Write-Host ""

$restrictanonymoussam = (Get-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Control\Lsa').restrictanonymoussam
if ($restrictanonymous -eq 1) {  
    Write-Host "“不允许SAM账户的匿名枚举值”为已启用"  -ForegroundColor Green 
} else {
    Write-Host "未禁用“不允许SAM账户的匿名枚举值”的安全策略"  -ForegroundColor Red
}
Write-Host ""
<#
# - 禁用磁盘共享(SMB)
Write-Host ">>>>>>>>>>>>>>>>>>>> [查看samba服务] <<<<<<<<<<<<<<<<<<<<" 
$samba = (Get-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Services\lanmanserver\parameters').AutoShareWks
if ($samba -eq 0) {  
    Write-Host "关闭禁用默认共享策略未启用"  -ForegroundColor Green 
} else {
    Write-Host "关闭禁用默认共享策略启用"  -ForegroundColor Red
}
Write-Host ""
AutoShareWks = @{regname="HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters";name="AutoShareWks";regtype="DWord";operator="eq";value=0;msg="关闭禁用默认共享策略-Server2012"}
AutoShareServer = @{regname="HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters";name="AutoShareServer";regtype="DWord";operator="eq";value=0;msg="关闭禁用默认共享策略-Server2012"}

#>
Write-Host ">>>>>>>>>>>>>>>>>>>> [高危端口] <<<<<<<<<<<<<<<<<<<<" 
Write-Host "当前运行端口信息一览" -ForegroundColor Yellow
netstat -an | findstr "LISTENING" | findstr "[20 21 22 23 25 135 139 137 445 593 1025 2745 3306 3389 3127 6129]$"
Write-Host ""

Write-Host "------------------------------- c）管理地址限制 -------------------------------" -BackgroundColor Magenta
Write-Host ">>>>>>>>>>>>>>>>>>>> [防火墙远程桌面 - 用户模式(TCP-In)] <<<<<<<<<<<<<<<<<<<<" 
<#
$address_rule = Get-NetFirewallRule  -DisplayName  '远程桌面 - 用户模式(TCP-In)' |Select *
$address_rule | Select-Object -Property DisplayName, Enabled, Profile, Direction, Action, RemoteAddress, LocalAddress, RemotePort
return $address_rule
#>
$firewall_area = (Get-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules')."RemoteDesktop-UserMode-In-TCP"
$firewall_area_parts = $firewall_area -split '\|' # 使用管道符号作为分隔符来分割字符串
$la4_value = ($firewall_area_parts | Where-Object { $_ -like 'LA4=*' } | Select-Object -First 1) -replace 'LA4=','' # 提取LA4的值
$ra4_value = ($firewall_area_parts | Where-Object { $_ -like 'RA4=*' } | Select-Object -First 1) -replace 'RA4=','' # 提取RA4的值
if ($la4_value -ne $null -and $ra4_value -ne $null) {  
    Write-Host "远程桌面 - 用户模式(TCP-In)作用域为本地地址：$($la4_value)，远程地址为：$($ra4_value)"  -ForegroundColor Green
} else {
    Write-Host "未设置远程桌面 - 用户模式(TCP-In)作用域"  -ForegroundColor Red
}
Write-Host ""

###########################################恶意代码防范################################################
Write-Host "************************************ 恶意代码防范 ************************************" -BackgroundColor DarkCyan
Write-Host "------------------------------- a）恶意代码防御 -------------------------------" -BackgroundColor Magenta
Write-Host ">>>>>>>>>>>>>>>>>>>> [是否安装防恶意代码软件] <<<<<<<<<<<<<<<<<<<<" 
Write-Host '查看是否防恶意代码软件，并进行截图（已保存在：该文件目录\screenshot\ScreenCapture），同时需要进入软件进行深度检查：' -ForegroundColor Yellow
appwiz.cpl
Start-Sleep -Milliseconds 800
Get-ScreenCapture
Write-Host ""


###########################################剩余信息保护################################################
Write-Host "************************************ 剩余信息保护 ************************************" -BackgroundColor DarkCyan
Write-Host "------------------------------- a）鉴别信息释放 -------------------------------" -BackgroundColor Magenta
Write-Host ">>>>>>>>>>>>>>>>>>>> [是否启用“交互式登录：不显示最后的用户名”策略] <<<<<<<<<<<<<<<<<<<<" 
$sam_release = (Get-ItemProperty -Path 'HKLM:Software\Microsoft\Windows\CurrentVersion\Policies\System').dontdisplaylastusername
if ($sam_release -eq 1) {  
    Write-Host "启用“交互式登录：不显示最后的用户名”策略，不显示显示上一次登陆的用户的用户名"  -ForegroundColor Green
} else {
    Write-Host "未启用“交互式登录：不显示最后的用户名”策略"  -ForegroundColor red
}
Write-Host ""

Write-Host "------------------------------- a）敏感信息释放 -------------------------------" -BackgroundColor Magenta
Write-Host ">>>>>>>>>>>>>>>>>>>> [是否启用“关机：清除虚拟内存页面文件”策略] <<<<<<<<<<<<<<<<<<<<" 
$sam_release = (Get-ItemProperty -Path 'HKLM:System\CurrentControlSet\Control\Session Manager\Memory Management').ClearPageFileAtShutdown
if ($sam_release -eq 1) {  
    Write-Host "已启用“关机：清除虚拟内存页面文件”策略"  -ForegroundColor Green
} else {
    Write-Host "未启用“关机：清除虚拟内存页面文件”策略"  -ForegroundColor red
}
Write-Host ""

}


########################################### 进行远程访问执行本地脚本——非域控制器 ################################################################################################
<#$serverName = Read-Host "请输入远程服务器的IP地址"
# 定义要执行的脚本块
# Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value "$serverName"
#Enter-PSSession $serverName -Credential $UserName
$session = New-PSSession -ComputerName $serverName
# 执行远程会话
Invoke-Command -ComputerName $serverName -FilePath "G:\工作\evaluation tools\windows\V0.9.ps1"
#>
Function Remote{
Write-Host "注意：若服务器为域控制器，账户填写格式：域名\用户名，比如：abc.com\Administrator" -ForegroundColor DarkGray
$serverName = Read-Host "请输入远程服务器的IP地址"
# 创建远程会话
$session = New-PSSession -ComputerName $serverName -Credential (Get-Credential)
# 在远程会话中执行命令
Invoke-Command -Session $session -ScriptBlock {

########################################### Information ################################################################################################
Write-Host "************************************ IP地址 ************************************"
$ipAddress = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex (Get-NetAdapter | Where-Object Status -eq 'Up').IfIndex).IPAddress   #获取当前系统上所有活动网络接口的IPv4地址。
(Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex (Get-NetAdapter | Where-Object Status -eq 'Up').IfIndex).IPAddress

########################################### 导出本地组策略配置 ################################################################################################
# 创建导出的文件名（使用.txt扩展名）
$path = (Get-Location).Path  
New-Item -Path "$path\screenshot" -ItemType Directory #创建截图所需的文件夹
$fileName = "$ipAddress~config.txt"
$combo_name = "$path\$fileName"
Write-Host "将组策略导出到当前执行脚本目录中($path)"# 输入实际导出路径
secedit /export /cfg $fileName /quiet

<#else {( $is_export_directory -eq "no" -or $is_export_directory -eq "n" )
	$userInput = Read-Host "请输入要导出的目录位置"
	Write-Host "组策略导出到$userInput"
	$diy_fileName = "$userInput\$fileName"
	secedit /export /cfg $diy_fileName /quiet
}#>
<# 判断比对本地组策略配置
########################################### 判断比对本地组策略配置 ################################################################################################
#判断文件的导出目录
if ( $is_export_directory -eq "yes" -or $is_export_directory -eq "y" ){
	$policyContent = Get-Content -Path $fileName
}else {( $is_export_directory -eq "no" -or $is_export_directory -eq "n" )
	$policyContent = Get-Content -Path $diy_fileName
}

# 创建一个哈希表来存储期望的值
$expectedPolicies = @{
    "MinimumPasswordAge" = @{value=30;msg="密码最短留存期"}
    "MaximumPasswordAge" = @{value=90;msg="密码最长留存期"}
    "PasswordComplexity" = @{value=1;msg="密码必须符合复杂性要求策略"}
	"MinimumPasswordLength" = @{value=8;msg="密码长度最小值"}
	"PasswordHistorySize" = @{value=3;msg="强制密码历史个记住的密码"}
	"LockoutBadCount" = @{value=6;msg="账户登录失败锁定阈值次数"}
	"ResetLockoutCount" = @{value=15;msg="账户锁定时间(分钟)"}
	"LockoutDuration" = @{value=15;msg="复位账户锁定计数器时间(分钟)"}
	"RequireLogonToChangePassword" = @{value=0;msg="下次登录必须更改密码"}
	"ForceLogoffWhenHourExpire" = @{value=0;msg="强制过期"}
	"NewAdministratorName" = @{value='"Administrator"';msg="当前系统默认管理账号登陆名称策略"}
	"NewGuestName" = @{value='"Guest"';msg="当前系统默认来宾用户登陆名称策略"}
	"EnableAdminAccount" = @{value=1;msg="管理员账户停用与启用策略"}
	"EnableGuestAccount" = @{value=0;msg="来宾账户停用与启用策略"}
	"AuditSystemEvents" = 0
	"AuditLogonEvents" = 0
	"AuditObjectAccess" = 0
	"AuditPrivilegeUse" = 0
	"AuditPolicyChange" = 0
	"AuditAccountManage" = 0
	"AuditProcessTracking" = 0
	"AuditDSAccess" = 0
	"AuditAccountLogon" = 0
    # ... 添加更多期望的策略和值
}

# 遍历每一行并检查是否与期望值匹配
foreach ($line in $policyContent) {
    $parts = $line -split "=" #将每一行按等号（=）分割成两部分，并存储在 $parts 数组中。
    if ($parts.Length -eq 2) {   #确保分割后的部分有两个（即策略名称和策略值）
        $policyName =$parts[0].Trim()  #去除分割后字符串两端的空白字符，并分别赋值给 $policyName 和 $policyValue。
        $policyValue =$parts[1].Trim()
        # 检查是否存在期望值，并比较
        if ($expectedPolicies.ContainsKey($policyName)) { 
            $expectedValue = $expectedPolicies[$policyName] # 检查哈希表 $expectedPolicies 中是否包含当前策略名称。
            if ($policyValue -eq $expectedValue.value) { # 如果包含，则获取期望的值 $expectedValue，并与实际的策略值 $policyValue 进行比较
                Write-Host "策略'$($expectedValue.msg)'的策略值为'$($expectedValue.value)'，判定为符合" -ForegroundColor Green
            } else {
                Write-Host "策略'$($expectedValue.msg)'与期望策略值不一致。期望值为'$($expectedValue.value)',实际值:'$policyValue'" -ForegroundColor Red  #需要双重调用$($
            }
		}
	}
}
#>
########################################### 函数模块化 #############################################
function Get-PolicyContent {
    param (
        [string]$fileName
    )
    $policyContent = Get-Content $fileName
    return $policyContent
}

function Check-PolicyCompliance {
    param (
        [string]$path,
        [hashtable]$expectedPolicies
    )

    # 定义文件名
    $fileName = "$ipAddress~config.txt"
    $combo_name = "$path\$fileName"

    # 获取策略内容
    $policyContent = Get-PolicyContent -fileName $combo_name

    # 遍历每一行并检查是否与期望值匹配
    foreach ($line in $policyContent) {
        $parts = $line -split "=" # 将每一行按等号（=）分割成两部分，并存储在 $parts 数组中。
        if ($parts.Length -eq 2) {   # 确保分割后的部分有两个（即策略名称和策略值）
            $policyName = $parts[0].Trim() # 去除分割后字符串两端的空白字符，并分别赋值给 $policyName 和 $policyValue。
            $policyValue = $parts[1].Trim()
            # 检查是否存在期望值，并比较
            if ($expectedPolicies.ContainsKey($policyName)) {
                $expectedValue = $expectedPolicies[$policyName]
                if ($policyValue -eq $expectedValue.value) {
                    Write-Host "策略'$($expectedValue.msg)'的策略值为'$($expectedValue.value)'，判定为符合" -ForegroundColor Green
                } else {
                    Write-Host "策略'$($expectedValue.msg)'与期望策略值不一致。期望值为'$($expectedValue.value)',实际值:'$policyValue'" -ForegroundColor Red
                }
            }
        }
    }
}
$path = (Get-Location).Path
function Put-PolicyCompliance {
    param (
        [string]$path,
        [hashtable]$expectedPolicies
    )

    # 定义文件名
    $fileName = "$ipAddress~config.txt"
    $combo_name = "$path\$fileName"

    # 获取策略内容
    $policyContent = Get-PolicyContent -fileName $combo_name

    # 遍历每一行并检查是否与期望值匹配
    foreach ($line in $policyContent) {
        $parts = $line -split "=" # 将每一行按等号（=）分割成两部分，并存储在 $parts 数组中。
        if ($parts.Length -eq 2) {   # 确保分割后的部分有两个（即策略名称和策略值）
            $policyName = $parts[0].Trim() # 去除分割后字符串两端的空白字符，并分别赋值给 $policyName 和 $policyValue。
            $policyValue = $parts[1].Trim()
            # 检查是否存在期望值，并比较
            if ($expectedPolicies.ContainsKey($policyName)) {
                $expectedValue = $expectedPolicies[$policyName]
                if ($policyValue -eq $expectedValue.value) {
                    Write-Host "策略'$($expectedValue.msg)'的值为'$($expectedValue.value)'" -ForegroundColor Yellow
                } else {
                    Write-Host "策略'$($expectedValue.msg)'与期望策略值不一致。期望值为'$($expectedValue.value)',实际值:'$policyValue'" -ForegroundColor Red
                }
            }
        }
    }
}

###########################################屏幕截图################################################
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.SendKeys]::SendWait("{PrtSc}")  
#$bitmap = [System.Windows.Forms.Clipboard]::GetImage()
function Get-ScreenCapture
{
    param(
    [Switch]$OfWindow
    )


    begin {
        Add-Type -AssemblyName System.Drawing
        $jpegCodec = [Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() |
            Where-Object { $_.FormatDescription -eq "JPEG" }
    }
    process {
        Start-Sleep -Milliseconds 300
        if ($OfWindow) {
            [Windows.Forms.Sendkeys]::SendWait("%{PrtSc}")
        } else {
            [Windows.Forms.Sendkeys]::SendWait("{PrtSc}")
        }
        Start-Sleep -Milliseconds 300
        $bitmap = [Windows.Forms.Clipboard]::GetImage()
        $ep = New-Object Drawing.Imaging.EncoderParameters
        $ep.Param[0] = New-Object Drawing.Imaging.EncoderParameter ([System.Drawing.Imaging.Encoder]::Quality, [long]100)
        $screenCapturePathBase = "$pwd\screenshot\ScreenCapture"
        $c = 0
        while (Test-Path "${screenCapturePathBase}${c}.jpg") {
            $c++
        }
        $bitmap.Save("${screenCapturePathBase}${c}.jpg", $jpegCodec, $ep)
    }
}
############################################# 核查是否以管理员权限进行登录 ################################################################################################
$user = [Security.Principal.WindowsIdentity]::GetCurrent(); 
$is_administrator = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) 
if ($is_administrator){
	Write-Host "已通过管理员身份运行该脚本" -ForegroundColor Green
}else {
	Write-Host "未以管理员身份运行该脚本，正在退出" -ForegroundColor red
	Write-Host "请以管理员身份再次运行该脚本" -ForegroundColor red
    return
}

########################################### Information ################################################################################################
Write-Host "************************************ IP地址 ************************************"
$ipAddress = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex (Get-NetAdapter | Where-Object Status -eq 'Up').IfIndex).IPAddress   #获取当前系统上所有活动网络接口的IPv4地址。
(Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex (Get-NetAdapter | Where-Object Status -eq 'Up').IfIndex).IPAddress

#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>windows server 2022<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<#
###########################################身份鉴别################################################
Write-Host "************************************ 身份鉴别 ************************************" -BackgroundColor DarkCyan
Write-Host ""
Write-Host "------------------------------- a）身份鉴别措施 -------------------------------" -BackgroundColor Magenta
Write-Host ""
# 是否具备身份鉴别措施
Write-Host ">>>>>>>>>>>>>>>>>>>> [是否存在自动登录鉴别措施:] <<<<<<<<<<<<<<<<<<<<"
$isChecked = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device').DevicePasswordLessBuildVersion  
if ($isChecked -eq 2) {  
    Write-Host "'DevicePasswordLessBuildVersion'键的值为2,(默认值为“2”,表示未开启选项框)"  -ForegroundColor Green
} else {
    Write-Host "'DevicePasswordLessBuildVersion'键的值为0,表示开启了选项框，需要进一步查看"  -ForegroundColor Yellow
}
Write-Host ""

# 选项框截图
Write-Host '查看“要使用本计算机，用户必须输入用户名和密码”的选项框，并进行截图（已保存在：该文件目录\screenshot\ScreenCapture）：' -ForegroundColor Yellow
Netplwiz.exe
Start-Sleep -Milliseconds 300
Get-ScreenCapture
Write-Host ""

$keyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$keys = @("DefaultUserName", "DefaultPassword", "AutoAdminLogon")

foreach ($key in $keys) {
    if (Test-Path $keyPath\$key) {
        $value = Get-ItemProperty $keyPath\$key
        Write-Host "$key 存在, 值为 $value" -ForegroundColor Red #第二种写法$value = (Get-ItemProperty -Path $keyPath\$key).$key则会在尝试获取注册表的值之前，先检查这个键是否存在
    } else {
        Write-Host "$key 不存在" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host '若同时配置“DevicePasswordLessBuildVersion”条目为0,“AutoAdminLogon”条目为1,会开启自动登录措施'
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [远程登录时是否采用身份鉴别机制:] <<<<<<<<<<<<<<<<<<<<"
$isChecked = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').LocalAccountTokenFilterPolicy
if ($isChecked -eq 1) {  
    Write-Host "'账户：使用空密码的本地帐户只允许进行控制台登录'选项已启用"  -ForegroundColor Green
} else {
    Write-Host "'账户：使用空密码的本地帐户只允许进行控制台登录'选项未启用"  -ForegroundColor Red
}

Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [策略'始终在连接时提示输入密码':] <<<<<<<<<<<<<<<<<<<<"
$isChecked = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services').fPromptForPassword
if ($isChecked -eq 1) {  
    Write-Host "'始终在连接时提示输入密码'选项已启用" -ForegroundColor Green
} else {
    Write-Host "'始终在连接时提示输入密码'选项未启用" -ForegroundColor Red
}
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [远程登录时策略'允许我保存凭证':] <<<<<<<<<<<<<<<<<<<<"
$isChecked = (Get-ItemProperty -Path 'HKLM:\SYSTEM\ControlSet001\Control\Terminal Server\WinStations\RDP-Tcp').fPromptForPassword
if ($isChecked -eq 1) {  
    Write-Host "将始终提示用户输入口令，即使密码是从以前的连接中保存的"  -ForegroundColor Green
} else {
    Write-Host "可以使用之前保存的口令"  -ForegroundColor Red
}
Write-Host ""

###########################################身份标识唯一性################################################
Write-Host ""
Write-Host "------------------------------- 身份标识唯一性 -------------------------------"
Write-Host ">>>>>>>>>>>>>>>>>>>> [核查账户列表，并访谈是否存在多人共用账户口令的情况] <<<<<<<<<<<<<<<<<<<<"
wmic useraccount get name,sid
Write-Host ""

###########################################口令复杂度################################################
Write-Host ""
Write-Host "------------------------------- 口令复杂度 -------------------------------"
Write-Host ">>>>>>>>>>>>>>>>>>>> [查询口令最小长度] <<<<<<<<<<<<<<<<<<<<"
$expectedPolicies = @{
    "MinimumPasswordLength" = @{value=8;msg="密码长度最小值"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""


Write-Host ">>>>>>>>>>>>>>>>>>>> [是否开启复杂度设置] <<<<<<<<<<<<<<<<<<<<"
$expectedPolicies = @{
    "PasswordComplexity" = @{value=1;msg="密码必须符合复杂性要求策略"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [密码最长留存期] <<<<<<<<<<<<<<<<<<<<"
$expectedPolicies = @{
    "MaximumPasswordAge" = @{value=90;msg="密码最长留存期"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

###########################################登录失败处理措施################################################
Write-Host ""
Write-Host "------------------------------- b）登录失败处理 -------------------------------" -BackgroundColor Magenta
Write-Host ">>>>>>>>>>>>>>>>>>>> [登录失败尝试次数] <<<<<<<<<<<<<<<<<<<<"
$expectedPolicies = @{
    "LockoutBadCount" = @{value=5;msg="账户登录失败锁定阈值次数"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [登录失败锁定时间] <<<<<<<<<<<<<<<<<<<<"
$expectedPolicies = @{
	"ResetLockoutCount" = @{value=15;msg="账户锁定时间(分钟)"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [屏幕保护程序是否启用] <<<<<<<<<<<<<<<<<<<<"
$isChecked = (Get-ItemProperty -Path 'HKCU:\Control Panel\Desktop').ScreenSaveActive
if ($isChecked -eq 1) {  
    Write-Host "已启用屏幕保护程序"  -ForegroundColor Green
} else {
    Write-Host "未启用屏幕保护程序"  -ForegroundColor Red
}
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [屏幕保护程序是否需要密码解锁] <<<<<<<<<<<<<<<<<<<<"
$isChecked_save = (Get-ItemProperty -Path 'HKCU:\Control Panel\Desktop').ScreenSaverIsSecure
if ($isChecked_save -eq 1) {  
    Write-Host "需要密码进行解锁"  -ForegroundColor Green
} else {
    Write-Host "不需要密码就可以解锁"  -ForegroundColor Red
}
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [屏幕保护程序设置超时时间] <<<<<<<<<<<<<<<<<<<<"
$isChecked_timeout = (Get-ItemProperty -Path 'HKCU:\Control Panel\Desktop').ScreenSaveTimeOut 
if($isChecked_timeout -eq 0){
	Write-Host "未设置屏幕保护程序超时时间" -ForegroundColor red
}elseif($isChecked_timeout -eq $null){
	Write-Host "未设置屏幕保护程序超时时间" -ForegroundColor red
}
elseif ($isChecked_timeout -le 900) {  
    Write-Host "屏幕保护程序超时时间合理，设置为:"$isChecked_timeout -NoNewline -ForegroundColor Green
	Write-Host "（秒）" -ForegroundColor Green
} else {
    Write-Host "屏幕保护程序超时时间过大，设置为:"$isChecked_timeout -NoNewline -ForegroundColor Red
	Write-Host "（秒）" -ForegroundColor Red
}
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [组策略中的“交互式登录：计算机不活动限制”值] <<<<<<<<<<<<<<<<<<<<"
$is_Security_Checked_timeout = (Get-ItemProperty -Path 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').InactivityTimeoutSecs 
#$decimal = [int]::Parse($is_Security_Checked_timeout, 16)  #转化16进制为10进制，但是默认就是输出十进制，白干活
if ($is_Security_Checked_timeout -eq 0) {  
    Write-Host "未设置用户不活动超时时间" -ForegroundColor Red
}elseif ($is_Security_Checked_timeout -eq $null) {  
    Write-Host "未设置用户不活动超时时间" -ForegroundColor Red
}elseif($is_Security_Checked_timeout -le 900){
	Write-Host "用户不活动超时时间合理，设置为:"$is_Security_Checked_timeout -NoNewline -ForegroundColor Green
	Write-Host "（秒）" -ForegroundColor Green
}else{
	Write-Host "用户不活动超时时间过大，设置为:"$is_Security_Checked_timeout -NoNewline -ForegroundColor Red
	Write-Host "（秒）" -ForegroundColor Red
}
Write-Host ""


Write-Host ">>>>>>>>>>>>>>>>>>>> [远程登录空闲后超时时间] <<<<<<<<<<<<<<<<<<<<"
$isChecked_remote_timeout = (Get-ItemProperty -Path 'HKLM:SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services').MaxIdleTime
$result=$isChecked_remote_timeout/1000
if ($result -eq 0) {  
	Write-Host "未设置远程登录空闲后超时时间" -ForegroundColor Red
} elseif($result -le 900){
    Write-Host "远程登录空闲后超时时间合理，设置为:"$result -NoNewline -ForegroundColor Green
	Write-Host "（秒）" -ForegroundColor Green
}else{
    Write-Host "远程登录空闲后超时时间不合理，设置为:"$result -NoNewline -ForegroundColor Red
	Write-Host "（秒）" -ForegroundColor Red
}
Write-Host ""

###########################################远程管理防窃听################################################
Write-Host ""
Write-Host "------------------------------- c）远程管理防窃听 -------------------------------" -BackgroundColor Magenta
Write-Host ">>>>>>>>>>>>>>>>>>>> [远程桌面登录服务使用的协议] <<<<<<<<<<<<<<<<<<<<"
$isChecked_remote = (Get-ItemProperty -Path 'HKLM:SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services').SecurityLayer
if ($isChecked_remote -eq 0) {  
    Write-Host "使用RDP进行身份验证"  -ForegroundColor yellow
} elseif ($isChecked_remote -eq 2) {
    Write-Host "使用TLS协议进行身份验证" -ForegroundColor Yellow
 }
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [远程客户端连接加密级别] <<<<<<<<<<<<<<<<<<<<"
$isChecked_remote = (Get-ItemProperty -Path 'HKLM:SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services').MinEncryptionLevel
if ($isChecked_remote -eq 3) {  
    Write-Host "加密级别为高级别"  -ForegroundColor Green
} else {
    Write-Host "加密级别未使用高级别" -ForegroundColor Red
}else{
	 Write-Host "未配置远程管理防窃听措施" -ForegroundColor red
 }
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [默认的远程客户端端口是否为3389] <<<<<<<<<<<<<<<<<<<<"
$RDP1 = (Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\').PortNumber
$RDP2 = (Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\Tds\tcp\').PortNumber
  if ( $RDP1 -eq $RDP2 -and $RDP2 -eq "3389") {
	Write-Host "默认的远程桌面端口为3389"  -ForegroundColor Yellow
  } else {
    Write-Host "默认的远程桌面端口已被修改为$($RDP1)"  -ForegroundColor Yellow
  }
###########################################访问控制################################################
Write-Host "************************************ 访问控制 ************************************" -BackgroundColor DarkCyan
Write-Host ""
Write-Host "------------------------------- a）账户分配、权限分配、权限限制 -------------------------------" -BackgroundColor Magenta
Write-Host ">>>>>>>>>>>>>>>>>>>> [用户信息表] <<<<<<<<<<<<<<<<<<<<"  -ForegroundColor yellow
Get-WmiObject -Class Win32_UserAccount  | Select-Object Disabled,Name,domain,FullName,AccountType,LocalAccount,Lockout,PasswordChangeable,PasswordRequired,SID,passwordexpires,Description
Write-Host ""


Write-Host ""
Write-Host ">>>>>>>>>>>>>>>>>>>> [用户权限分配与限制] <<<<<<<<<<<<<<<<<<<<"
$acl = icacls "C:\windows\system" | findstr "Guest"
                if ($acl -eq $null) {
                    Write-Host "不存在Guest账户对C:\windows\system文件夹等重要客体具备任何权限" -ForegroundColor Green
                } else {
                    Write-Host "存在Guest账户对C:\windows\system文件夹等重要客体具备权限。" -ForegroundColor Red
                }
Write-Host ""
$acl = icacls "C:\windows\system" | findstr "Everyone"
                if ($acl -eq $null) {
                    Write-Host "不存在Everyone账户对C:\windows\system文件夹等重要客体具备任何权限" -ForegroundColor Green
                } else {
                    Write-Host "存在Everyone账户对C:\windows\system文件夹等重要客体具备权限。" -ForegroundColor Red
                }
Write-Host ""


Write-Host "------------------------------- b）默认账户 -------------------------------" -BackgroundColor Magenta
Write-Host ">>>>>>>>>>>>>>>>>>>> [默认账户Administrator和Guest状态] <<<<<<<<<<<<<<<<<<<<"
$expectedPolicies = @{
    "NewAdministratorName" = @{value='"Administrator"';msg="当前系统默认管理账号登陆名称"}
}
Put-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

$expectedPolicies = @{
    "NewGuestName" = @{value='"Guest"';msg="当前系统默认来宾用户登陆名称"}
}
Put-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [查看默认账户的是否被禁用或重命名] <<<<<<<<<<<<<<<<<<<<" 
$users = Get-WmiObject -Class Win32_UserAccount -Filter "Name='Guest' OR Name='Administrator'" | Select-Object Disabled,Name,domain,FullName,Lockout
foreach ($user in $users) {
    if ($user.Disabled -eq $true) {
        Write-Host "$($user.Name)用户账户已被禁用。" -ForegroundColor green
    } else {
        Write-Host "$($user.Name)用户账户未被禁用。" -ForegroundColor red
    }
}
Write-Host ""
<# 查看默认账户的是否被禁用或重命名
Write-Host ">>>>>>>>>>>>>>>>>>>> [查看默认账户的是否被禁用或重命名] <<<<<<<<<<<<<<<<<<<<" 
$users = Get-WmiObject -Class Win32_UserAccount -Filter "Name='Administrator' OR Name='Guest'" | Select-Object Disabled,Name,domain,FullName,Lockout
foreach ($user in $users) {
    if ($user.Disabled -eq $true) {
        Write-Host "$($user.Name)用户账户已被禁用。" -ForegroundColor green
    } else {
        Write-Host "$($user.Name)用户账户未被禁用。" -ForegroundColor red
    }
}
#>
<# 用户信息表解析
Disabled: 这个属性表示账户是否被禁用。如果账户被禁用，这个属性通常为 True。

Name: 这是用户账户的登录名，也就是用户用来登录系统的名字。

Domain: 表示用户账户所属的域。如果是本地账户，通常显示为计算机的名称。

FullName: 用户的全名，通常比登录名更正式，包含了用户的名字和姓氏。

LocalAccount: 这个属性指示账户是本地账户还是域账户。对于本地账户，此属性通常为 True。

Lockout: 表示账户是否被锁定，通常是由于多次尝试使用错误的密码登录。

PasswordChangeable: 这个属性指示用户是否能够更改其密码。

PasswordRequired: 如果这个属性为 True，则表示用户必须有一个密码才能登录。

SID: 安全标识符（Security Identifier）是一个唯一的标识符，用来在安全上下文中唯一标识用户、用户组、计算机账户或其他安全主体。

PasswordExpires: 这个属性表示密码到期的日期，超过这个日期用户需要更改密码。

Description: 账户的描述，通常包含关于账户用途或用户的额外信息。

AccountType:账户的类型，如用户账户、管理员账户等。
	512 (0x0200) - 表示本地用户账户（Local User Account）。

	268435456 (0x10000000) - 表示域用户账户（Domain User Account）。

	536870912 (0x20000000) - 表示本地管理员账户（Local Administrator Account）。这个值通常与本地用户账户（512）组合使用，例如 512 + 536870912 = 536871424，表示该账户既是本地用户也是本地管理员。

	805306368 (0x30000000) - 表示域管理员账户（Domain Administrator Account）。这个值可能与域用户账户（268435456）组合使用，表示该账户既是域用户也是域管理员。
#>

Write-Host "------------------------------- c）多余、过期和共享的账户 -------------------------------" -BackgroundColor Magenta
Write-Host ">>>>>>>>>>>>>>>>>>>> [多余、过期的账户自行访谈核查] <<<<<<<<<<<<<<<<<<<<" -ForegroundColor Yellow
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [共享的账户] <<<<<<<<<<<<<<<<<<<<"
# 获取 ID 为 4648 的所有事件日志
$logName = 'Security'
$eventId = 4648
$local_path = (Get-Location).Path  
$share_Nickname = '共享账户.txt'
$share_name = "$local_path\$share_Nickname"
$events = Get-WinEvent -FilterHashtable @{LogName=$logName; ID=$eventId} | Format-List -Property TimeCreated, ProviderName, Message 
# 检查是否找到事件并显示它们
if ($events -eq $null) {
    Write-Host "未找到ID为$($eventId)的事件"  -ForegroundColor Red
} else {
	$events_save = Get-WinEvent -FilterHashtable @{LogName=$logName; ID=$eventId} | Format-List -Property TimeCreated, ProviderName, Message >>$share_name
    Write-Host "已找到ID为$($eventId)的事件，已存储到脚本自身所在目录的'共享账户.txt'中"  -ForegroundColor Yellow
}
Write-Host ""

Write-Host "------------------------------- d）最小权限 -------------------------------" -BackgroundColor Magenta
Write-Host ">>>>>>>>>>>>>>>>>>>> [用户角色划分最小权限] <<<<<<<<<<<<<<<<<<<<"
$groups = Get-LocalGroup

foreach ($group in $groups) {
  $members = Get-LocalGroupMember -Group $group.Name
  if($members -eq $null){
	  Write-Host "组名 - ($($group.Name)):"  -NoNewline
	  Write-Host "组内未存在用户" -ForegroundColor DarkGray
  }else{
	  Write-Host "组名 - ($($group.Name)):"
  }
  $members | Select-Object Name | Sort-Object Name | ForEach-Object {
    Write-Host "    组内用户：$($_.Name)" -ForegroundColor yellow
  }
}
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [组策略的用户权限分配] <<<<<<<<<<<<<<<<<<<<"
#  操作系统本地关机策略安全
$expectedPolicies = @{
    SeShutdownPrivilege = @{value='*S-1-5-32-544';msg="操作系统本地关机策略"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

#操作系统远程关机策略安全
$expectedPolicies = @{
    SeRemoteShutdownPrivilege = @{value='*S-1-5-32-544';msg="操作系统远程关机策略"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

#取得文件或其他对象的所有权限策略
$expectedPolicies = @{
    SeProfileSingleProcessPrivilege = @{value='*S-1-5-32-544';msg="取得文件或其他对象的所有权限策略"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

#从网络访问此计算机策略
$expectedPolicies = @{
    SeNetworkLogonRight = @{value='*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551';msg="从网络访问此计算机策略"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

Write-Host "SID对应表"  -ForegroundColor Yellow
Write-Host "S-1-5-32-544 Administrators（用户组）" -ForegroundColor DarkGray
Write-Host "S-1-5-32-545 Users（用户组）" -ForegroundColor DarkGray
Write-Host "S-1-5-32-546 Guest（用户组）" -ForegroundColor DarkGray
Write-Host "S-1-5-32-548 Account Operators（用户组）" -ForegroundColor DarkGray
Write-Host "S-1-5-32-549 Server Operators（用户组）" -ForegroundColor DarkGray
Write-Host "S-1-5-32-550 Print Operators（用户组）" -ForegroundColor DarkGray
Write-Host "S-1-5-32-551 Backup Operators（用户组）" -ForegroundColor DarkGray
Write-Host "S-1-5-32-573 Event Log Readers（用户组）" -ForegroundColor DarkGray
Write-Host "S-1-1-0 Everyone（用户）" -ForegroundColor DarkGray
Write-Host ""
<#
S-1-5-32-544	管理员	内置组。 初始安装操作系统后，组的唯一成员是 Administrator 帐户。 当计算机加入域时，“Domain Admins”组将添加到管理员组。 当服务器成为域控制器时，“Enterprise Admins”组也会被添加到管理员组。
S-1-5-32-545	使用者	內建群組。 在初始安裝作業系統之後，唯一成員是 Authenticated Users/Users 群組。
S-1-5-32-546	来宾	内置组。 默认情况下，唯一的成员是 Guest 帐户。 Guests 组允许偶尔或一次性用户以有限的权限登录计算机的内置 Guest 帐户。
S-1-5-32-547	超级用户	内置组。 默认情况下，该组没有任何成员。 超级用户可以创建本地用户和组；修改和删除已创建的帐户；以及从 Power Users、Users 和 Guests 组中删除用户。 超级用户也可以安装程序；创建、管理和删除本地打印机；以及创建和删除文件共享。
S-1-5-32-548	Account Operators	仅存在于域控制器上的内置组。 默认情况下，该组没有任何成员。 默认情况下，Account Operators 有权在 Active Directory 的所有容器和组织单位（内置容器和域控制器 OU 除外）中创建、修改和删除用户、组和计算机的帐户。 帐户操作员无权修改 Administrators 和 Domain Admins 组，也无权修改这些组的成员的帐户。
S-1-5-32-549	Server Operators	说明：仅存在于域控制器上的内置组。 默认情况下，该组没有任何成员。 Server Operators 可以交互式登录到服务器；创建和删除网络共享；启动和停止服务；备份和恢复文件；格式化计算机硬盘；然后关闭计算机。
S-1-5-32-550	打印操作员	仅存在于域控制器上的内置组。 默认情况下，唯一的成员是“Domain Users”组。 Print Operators 可以管理打印机和文档队列。
S-1-5-32-551	备份操作员	内置组。 默认情况下，该组没有任何成员。 Backup Operators 可以备份和还原计算机上的所有文件，而不管保护这些文件的权限如何。 Backup Operators 还可以登录到计算机并关闭计算机。
S-1-1-0	  		Everyone，包括所有用户的组。
#>

###########################################安全审计################################################
Write-Host "************************************ 安全审计 ************************************" -BackgroundColor DarkCyan
Write-Host ""
Write-Host "------------------------------- a）安全审计范围 -------------------------------" -BackgroundColor Magenta
Write-Host "Windows操作系统默认开启日志记录功能，且无法停用审计服务进程"  -ForegroundColor yellow
Write-Host ""
Write-Host ">>>>>>>>>>>>>>>>>>>> [本地策略的审计范围] <<<<<<<<<<<<<<<<<<<<" 
#审核策略更改 其中无审核为0，单开启成功为1，单开启失败为2，成功和失败都开启为3
$expectedPolicies = @{
   AuditPolicyChange = @{value=3;msg="审核策略更改"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

#审核登录事件
$expectedPolicies = @{
   AuditLogonEvents = @{value=3;msg="审核登录事件"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

#审核对象访问
$expectedPolicies = @{
   AuditObjectAccess = @{value=3;msg="审核对象访问"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

#审核过程追踪
$expectedPolicies = @{
   AuditProcessTracking = @{value=3;msg="审核过程追踪"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

#审核目录服务访问
$expectedPolicies = @{
   AuditDSAccess = @{value=3;msg="审核目录服务访问"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

#审核特权使用
$expectedPolicies = @{
   AuditPrivilegeUse = @{value=3;msg="审核特权使用"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

#审核系统事件
$expectedPolicies = @{
   AuditSystemEvents = @{value=3;msg="审核系统事件"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

#审核账户登录事件
$expectedPolicies = @{
   AuditAccountLogon = @{value=3;msg="审核账户登录事件"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

#审核账户管理
$expectedPolicies = @{
   AuditAccountManage = @{value=3;msg="审核账户管理"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""
Write-Host "****说明：无审核为0，单开启成功为1，单开启失败为2，成功和失败都开启为3****"  -ForegroundColor Darkgray
Write-Host ""


Write-Host "------------------------------- b）安全审计规则 -------------------------------" -BackgroundColor Magenta
Write-Host ""
Write-Host ">>>>>>>>>>>>>>>>>>>> [当前时间戳] <<<<<<<<<<<<<<<<<<<<" 
#获取系统时间
$Date = Get-Date 
Write-Host "$($Date)" -ForegroundColor Yellow
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [时钟同步（此项不做强制要求）] <<<<<<<<<<<<<<<<<<<<" 
#获取NTP时钟设备
$NTP = (Get-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer').Enabled
$NTP_addr = (Get-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Services\W32Time\Parameters').NtpServer
if ( $NTP -eq 1) {
    Write-Host "用户设置并启用了NTP服务器，查看设置NTP服务的地址为:$($NTP_addr)" -ForegroundColor Yellow
} else {
    Write-Host "用户设置未启用NTP服务器" -ForegroundColor Yellow
}
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [安全审计规则] <<<<<<<<<<<<<<<<<<<<" 
Write-Host "Windows操作系统默认规定审计信息规则，均包含日期和时间、主体标识、任务类型、事件ID、关键字、客体标识、结果等信息。"  -ForegroundColor Yellow


Write-Host "------------------------------- c）安全审计保护 -------------------------------" -BackgroundColor Magenta
Write-Host ""
#用户权限分配的管理审核和安全日志
Write-Host "*S-1-5-32-573为Event Log Readers用户组"
$expectedPolicies = @{
   SeSecurityPrivilege = @{value='*S-1-5-32-573';msg="管理审核和安全日志"}
}
Check-PolicyCompliance -path $path -expectedPolicies $expectedPolicies
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [日志最大大小] <<<<<<<<<<<<<<<<<<<<" 
$EventlogSystemMaxSize = (Get-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Services\Eventlog\System').MaxSize / 1024
if ($EventlogSystemMaxSize -le 1048576) {  
    Write-Host "系统日志查看器大小设置可能过小，设置为$($EventlogSystemMaxSize)(KB)"  -ForegroundColor Yellow 
} else {
    Write-Host "系统日志查看器大小设置合理，设置为$($EventlogSystemMaxSize)"  -ForegroundColor Yellow
}
Write-Host ""

$EventlogApplicationMaxSize = (Get-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Services\Eventlog\Application').MaxSize  / 1024
if ($EventlogApplicationMaxSize -le 1048576) {  
    Write-Host "应用程序日志查看器大小设置可能过小，设置为$($EventlogApplicationMaxSize)(KB)"  -ForegroundColor Yellow 
} else {
    Write-Host "应用程序日志查看器大小设置合理，设置为$($EventlogApplicationMaxSize)"  -ForegroundColor Yellow
}
Write-Host ""

$EventlogSecurityMaxSize = (Get-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Services\Eventlog\Security').MaxSize  / 1024
if ($EventlogSecurityMaxSize -le 1048576) {  
    Write-Host "安全日志查看器大小设置可能过小，设置为$($EventlogSecurityMaxSize)(KB)"  -ForegroundColor Yellow 
} else {
    Write-Host "安全日志查看器大小设置合理，设置为$($EventlogSecurityMaxSize)"  -ForegroundColor Yellow
}
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [达到事件日志最大大小时的操作] <<<<<<<<<<<<<<<<<<<<" 
$EventlogSystemMaxSize = (Get-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Services\Eventlog\System').AutoBackupLogFiles
if ($EventlogApplicationMaxSize -eq 1) {  
	Write-Host "系统日志满时将其存档，不覆盖事件"  -ForegroundColor Green 
} else {
    Write-Host "系统日志满时，按需要覆盖事件或不覆盖事件(手动清除日志)"  -ForegroundColor Yellow
}
Write-Host ""

$EventlogApplicationMaxSize = (Get-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Services\Eventlog\Application').AutoBackupLogFiles
if ($EventlogApplicationMaxSize -eq 1) {  
    Write-Host "应用程序日志满时将其存档，不覆盖事件"  -ForegroundColor Green 
} else {
    Write-Host "应用程序日志满时，按需要覆盖事件或不覆盖事件(手动清除日志)"  -ForegroundColor Yellow
}
Write-Host ""

$EventlogSecurityMaxSize = (Get-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Services\Eventlog\Security').AutoBackupLogFiles
if ($EventlogSecurityMaxSize -eq 1) {  
    Write-Host "安全日志满时将其存档，不覆盖事件"  -ForegroundColor Green 
} else {
    Write-Host "安全日志满时，按需要覆盖事件或不覆盖事件(手动清除日志)"  -ForegroundColor Yellow
}
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [审计备份] <<<<<<<<<<<<<<<<<<<<" 
<# 未测试完
Add-PSSnapin WindowsServerBackup
Get-WBSummary
Write-Host ""
#>


###########################################入侵防范################################################
Write-Host "************************************ 入侵防范 ************************************" -BackgroundColor DarkCyan
Write-Host ""
Write-Host "------------------------------- a）最小化原则 -------------------------------" -BackgroundColor Magenta
Write-Host ">>>>>>>>>>>>>>>>>>>> [最小化安装] <<<<<<<<<<<<<<<<<<<<" 
$MIN_install = Get-WmiObject -Class Win32_Product | Select-Object -Property Name,Version,IdentifyingNumber | Sort-Object Name | Out-String
Write-Host "$($MIN_install)" -ForegroundColor Yellow

Write-Host ""

Write-Host "------------------------------- b）最小化服务、默认共享、高危端口 -------------------------------" -BackgroundColor Magenta
Write-Host ">>>>>>>>>>>>>>>>>>>> [最小化服务] <<<<<<<<<<<<<<<<<<<<" 
$serviceNames = 'RemoteRegistry', 'Alerter','Bluetooth*', 'Clipbook','Computer Browser','Messenger','Routing and Remote Access','Simple Mail Trasfer Protocol','Simple Network、Management Protocol','Telnet','Print Spooler','Automatic Updates'
Get-Service -Name $serviceNames -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' } | Select-Object -Property Name, Status 
Write-Host ""

Write-Host ">>>>>>>>>>>>>>>>>>>> [默认共享] <<<<<<<<<<<<<<<<<<<<" 
# - 检查关闭默认共享盘
$restrictanonymous = (Get-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Control\Lsa').restrictanonymous
if ($restrictanonymous -eq 1) {  
    Write-Host "系统网络基配核查-关闭默认共享盘策略"  -ForegroundColor Green 
} else {
    Write-Host "未关闭默认共享盘策略"  -ForegroundColor Red
}
Write-Host ""

$restrictanonymoussam = (Get-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Control\Lsa').restrictanonymoussam
if ($restrictanonymous -eq 1) {  
    Write-Host "“不允许SAM账户的匿名枚举值”为已启用"  -ForegroundColor Green 
} else {
    Write-Host "未禁用“不允许SAM账户的匿名枚举值”的安全策略"  -ForegroundColor Red
}
Write-Host ""
<#
# - 禁用磁盘共享(SMB)
Write-Host ">>>>>>>>>>>>>>>>>>>> [查看samba服务] <<<<<<<<<<<<<<<<<<<<" 
$samba = (Get-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Services\lanmanserver\parameters').AutoShareWks
if ($samba -eq 0) {  
    Write-Host "关闭禁用默认共享策略未启用"  -ForegroundColor Green 
} else {
    Write-Host "关闭禁用默认共享策略启用"  -ForegroundColor Red
}
Write-Host ""
AutoShareWks = @{regname="HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters";name="AutoShareWks";regtype="DWord";operator="eq";value=0;msg="关闭禁用默认共享策略-Server2012"}
AutoShareServer = @{regname="HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters";name="AutoShareServer";regtype="DWord";operator="eq";value=0;msg="关闭禁用默认共享策略-Server2012"}

#>
Write-Host ">>>>>>>>>>>>>>>>>>>> [高危端口] <<<<<<<<<<<<<<<<<<<<" 
Write-Host "当前运行端口信息一览" -ForegroundColor Yellow
netstat -an | findstr "LISTENING" | findstr "[20 21 22 23 25 135 139 137 445 593 1025 2745 3306 3389 3127 6129]$"
Write-Host ""

Write-Host "------------------------------- c）管理地址限制 -------------------------------" -BackgroundColor Magenta
Write-Host ">>>>>>>>>>>>>>>>>>>> [防火墙远程桌面 - 用户模式(TCP-In)] <<<<<<<<<<<<<<<<<<<<" 
<#
$address_rule = Get-NetFirewallRule  -DisplayName  '远程桌面 - 用户模式(TCP-In)' |Select *
$address_rule | Select-Object -Property DisplayName, Enabled, Profile, Direction, Action, RemoteAddress, LocalAddress, RemotePort
return $address_rule
#>
$firewall_area = (Get-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules')."RemoteDesktop-UserMode-In-TCP"
$firewall_area_parts = $firewall_area -split '\|' # 使用管道符号作为分隔符来分割字符串
$la4_value = ($firewall_area_parts | Where-Object { $_ -like 'LA4=*' } | Select-Object -First 1) -replace 'LA4=','' # 提取LA4的值
$ra4_value = ($firewall_area_parts | Where-Object { $_ -like 'RA4=*' } | Select-Object -First 1) -replace 'RA4=','' # 提取RA4的值
if ($la4_value -ne $null -and $ra4_value -ne $null) {  
    Write-Host "远程桌面 - 用户模式(TCP-In)作用域为本地地址：$($la4_value)，远程地址为：$($ra4_value)"  -ForegroundColor Green
} else {
    Write-Host "未设置远程桌面 - 用户模式(TCP-In)作用域"  -ForegroundColor Red
}
Write-Host ""

###########################################恶意代码防范################################################
Write-Host "************************************ 恶意代码防范 ************************************" -BackgroundColor DarkCyan
Write-Host "------------------------------- a）恶意代码防御 -------------------------------" -BackgroundColor Magenta
Write-Host ">>>>>>>>>>>>>>>>>>>> [是否安装防恶意代码软件] <<<<<<<<<<<<<<<<<<<<" 
Write-Host '查看是否防恶意代码软件，并进行截图（已保存在：该文件目录\screenshot\ScreenCapture），同时需要进入软件进行深度检查：' -ForegroundColor Yellow
appwiz.cpl
Start-Sleep -Milliseconds 800
Get-ScreenCapture
Write-Host ""


###########################################剩余信息保护################################################
Write-Host "************************************ 剩余信息保护 ************************************" -BackgroundColor DarkCyan
Write-Host "------------------------------- a）鉴别信息释放 -------------------------------" -BackgroundColor Magenta
Write-Host ">>>>>>>>>>>>>>>>>>>> [是否启用“交互式登录：不显示最后的用户名”策略] <<<<<<<<<<<<<<<<<<<<" 
$sam_release = (Get-ItemProperty -Path 'HKLM:Software\Microsoft\Windows\CurrentVersion\Policies\System').dontdisplaylastusername
if ($sam_release -eq 1) {  
    Write-Host "启用“交互式登录：不显示最后的用户名”策略，不显示显示上一次登陆的用户的用户名"  -ForegroundColor Green
} else {
    Write-Host "未启用“交互式登录：不显示最后的用户名”策略"  -ForegroundColor red
}
Write-Host ""

Write-Host "------------------------------- a）敏感信息释放 -------------------------------" -BackgroundColor Magenta
Write-Host ">>>>>>>>>>>>>>>>>>>> [是否启用“关机：清除虚拟内存页面文件”策略] <<<<<<<<<<<<<<<<<<<<" 
$sam_release = (Get-ItemProperty -Path 'HKLM:System\CurrentControlSet\Control\Session Manager\Memory Management').ClearPageFileAtShutdown
if ($sam_release -eq 1) {  
    Write-Host "已启用“关机：清除虚拟内存页面文件”策略"  -ForegroundColor Green
} else {
    Write-Host "未启用“关机：清除虚拟内存页面文件”策略"  -ForegroundColor red
}
Write-Host ""

}

}

#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>判断是本地执行还是远程执行<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<#
if ($args[0] -eq $null) { 
	Write-Host "请您决定是本地或远程执行该脚本（在命令后加-r或-l，详细可见帮助文档）" -ForegroundColor Red
}

if ($args[0] -eq "-r") {  
    Remote 
	exit 0
}elseif ($args[0] -eq "-l"){
	Main
	exit 0
}

<# switch也是可以实现的，等后期添加域的检测后用switch
switch ($args[0])
{
    -r #若数值为表达式，且有空格，则要加括号
    {
        Remote
    }
    -l
    {
        Main
    }
}
#>

########################################### 进行远程访问执行本地脚本——域控制器 ################################################################################################
