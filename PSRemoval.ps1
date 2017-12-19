<#Clear Typical AV Directories
    This script is meant to speed up normal AV alert cleanup processes, since clearing the same directories each time is standard.

    CHANGELOG:
    20171103-1356: Adding -Force & -Recurse to the Remove-Item lines.
    20171103-1036: Using Start-Transcript for loggin, & better First Use handling.
    20171103: Want to try & use the Test-Connection cmdlet so I can stop the script if the host is inaccessable.
    20171102-1600: Adding in the win7 directories:
        C:\Users\<< USERNAME >>\AppData\Local\Google\Chrome\User Data\Default\Cache\*
        C:\Users\<< USERNAME >>\AppData\Local\Google\Chrome\User Data\Default\Application Cache\Cache\
        C:\Users\<< USERNAME >>\AppData\Local\Microsoft\Windows\Temporary Internet Files\
            \Content.IE5\
            \Content.Outlook\
            \Low\Content.IE5\
    20171102-10:31: Right now, this will work for win8+. I'll need to add entries for win7 devices.

#>
<#
    Here's an example to base the script off of:
        PS C:\WINDOWS\system32> $workstation = "127.0.0.1"
        PS C:\WINDOWS\system32> Get-WMIObject -ComputerName $workstation -Class Win32_ComputerSystem | Select Username > C:\Windows\Temp\FQDN_Username.txt
        PS C:\WINDOWS\system32> $FQDN_User = Get-Content C:\Windows\Temp\FQDN_Username.txt | Select -Index 3
        PS C:\WINDOWS\system32> $FQDN_User = $FQDN_User.Replace("CVSTARRCO\","")
        PS C:\WINDOWS\system32> $FQDN_User
            Sean.McAdam
        PS C:\WINDOWS\system32>
#>

<#
    # Check to make sure this is being Run as Administrator
    $runningAsAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")

    If ($runningAsAdmin != True) {
        Write-Host -ForegroundColor Red "Please restart your CMD, PowerShell, or this script to Run As Administrator."
    }
#>

Param (
    [Parameter(Mandatory=$true)]
    [String]$Workstation
)
# if(-not($Workstation)){ Throw "You must enter a Hostname or IP!" }

# Adding Logging Functions...
# . "C:\Scripts\Functions\Logging_Functions.ps1"

# Request the Hostname or IP of the workstation
# Source: https://technet.microsoft.com/en-us/library/ee176935.aspx
# $Workstation = Read-Host "Please enter the Hostname or IP Address of the affected workstation"

$scriptsLogsDir = Test-Path C:\Scripts\Logs
if ($scriptsLogsDir -ne $True) {
    New-Item -Type Directory C:\Scripts\Logs
    # New-Item -Type File C:\Scripts\Logs\Clear_Dir_for_AV.log
    "" | Out-File C:\Scripts\Logs\Clear_Dir_for_AV.log
} else {
    "The path exists."
}

Start-Transcript -Path C:\Scripts\Logs\Clear_Dir_for_AV.log -Append

Write-Host -ForegroundColor Cyan "# # # # # # # # # # # # # # # # # # # # # # # # # # #"
# Write-Host -ForegroundColor Cyan "#                                                   #"
Write-Host -ForegroundColor Cyan "# Script for clearing typical malware directories.  #"
Write-Host -ForegroundColor Cyan "# Last Update: 20171103-1357                        #"
Write-Host -ForegroundColor Cyan "# Author: SMc                                       #"
Write-Host -ForegroundColor Cyan "# v.0.5                                             #"
# Write-Host -ForegroundColor Cyan "#                                                   #"
Write-Host -ForegroundColor Cyan "# # # # # # # # # # # # # # # # # # # # # # # # # # #"

# Logging Setup:
$logPath = "C:\Scripts\Logs\Clear_Dir_for_AV\"
$logDirectoryExists = Test-Path "C:\Scripts\Logs\Clear_Dir_for_AV\"
If ($logDirectoryExists -ne $True) {
    Write-Host -ForegroundColor Red "Log path not detected. Creating now..."
    New-Item -Type Directory $logPath
} else {
    Write-Host -ForegroundColor Green "Log directory detected."
}

# Get-Date -Format yyMMdd
$logFilename = Get-Date -Format yyyyMMdd
$logFilename = $logFilename + "-" + $Workstation + ".log"

# $logExists = Test-Path C:\Scripts\Logs\Clear_Dir_for_AV\$logFilename
$logExists = Test-Path C:\Scripts\Logs\Clear_Dir_for_AV
if ($logExists -ne $True) {
    New-Item -Type Directory $logPath#\$logFilename
    # New-Item -Type File $logPath\$logFilename
} else {
    Write-Host -ForegroundColor Green "Using previously created log file" $logFilename
}
$fullLogPath = $logPath + $logFilename

$dateTimeStamp = Get-Date -Format g
"Date, Time: `t $dateTimeStamp" | Out-File $fullLogPath -Encoding ASCII -Append
"Workstation: `t $Workstation" | Out-File $fullLogPath -Encoding ASCII -Append

# Test-Connection Setup
# https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/test-connection?view=powershell-5.1
if (Test-Connection -ComputerName $Workstation -Quiet) {

    Write-Host "Checking if host is online..."
    
    # Get the currently logged-on user
    Write-Host ""
    Write-Host -ForegroundColor White "Getting the currently logged on user..."
    Get-WmiObject -ComputerName $Workstation -Class Win32_ComputerSystem | Select Username > C:\Windows\Temp\FQDN_Username.txt
    $FQDN_User = Get-Content C:\Windows\Temp\FQDN_Username.txt | Select -Index 3
    $FQDN_User = $FQDN_User.Replace("CVSTARRCO\","")
    Write-Host ""
    Write-Host -ForegroundColor Green "Current User on $Workstation is $FQDN_User."
    Write-Host ""

    $currentUser = $FQDN_User

    "Current User: `t $currentUser" | Out-File $fullLogPath -Encoding ASCII -Append

    # Write-Host $currentUser

    <#
        Now that we have the username, time to start cleaning directories...
        Here's the list to clear:
            Windows 10:
                C:\Windows\Temp\
                C:\Users\<< USERNAME >>\AppData\Local\Microsoft\Windows\IECompatCache\
                C:\Users\<< USERNAME >>\AppData\Local\Microsoft\Windows\IECompatUaCache\
                C:\Users\<< USERNAME >>\AppData\Local\Microsoft\Windows\IEDownloadHistory\
                C:\Users\<< USERNAME >>\AppData\Local\Microsoft\Windows\INetCache\IE\
                C:\Users\<< USERNAME >>\AppData\Local\Microsoft\Windows\INetCache\Low\
                C:\Users\<< USERNAME >>\AppData\Local\Microsoft\Windows\INetCookies\Low\
                C:\Users\<< USERNAME >>\AppData\Local\Microsoft\Windows\INetCookies\PrivacIE\Low\
                C:\Users\<< USERNAME >>\AppData\Local\Temp\
                C:\Users\<< USERNAME >>\AppData\LocalLow\Sun\… *** HAVE TO CHECK THIS ONE ***
                C:\Users\<< USERNAME >>\AppData\Roaming\Macromedia\Flash Player\#SharedObjects\
    #>

    # Will be using the Remove-Item cmdlet
    Write-Host -ForegroundColor Yellow "Clearing C:\Windows\Temp\..."
    "Clearing C:\Windows\Temp\..." | Out-File $fullLogPath -Encoding ASCII -Append
    Remove-Item -Recurse -Force "\\$Workstation\c$\Windows\Temp\*"
    "`t `t Path: \\$Workstation\c$\Windows\Temp\" | Out-File $fullLogPath -Encoding ASCII -Append

    # Should create a variable I can through in for that path. Don't need to fill it out each time.
    $LocalAppDataDirectories = "\\$Workstation\c$\Users\$currentUser\AppData\Local"
    $LocalAppDataLabel = "C:\Users\$currentUser\AppData\Local"

    Write-Host -ForegroundColor Yellow "Clearing $LocalAppDataLabel\Temp\..."
    "Clearing $LocalAppDataLabel\Temp\..." | Out-File $fullLogPath -Encoding ASCII -Append
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$LocalAppDataDirectories\Temp\*"
    "`t `t Path: $LocalAppDataDirectories\Temp\" | Out-File $fullLogPath -Encoding ASCII -Append

    Write-Host -ForegroundColor Yellow "Clearing $LocalAppDataLabel\Microsoft\Windows\IECompatCache\..."
    "Clearing $LocalAppDataLabel\Microsoft\Windows\IECompatCache\..." | Out-File $fullLogPath -Encoding ASCII -Append
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$LocalAppDataDirectories\Microsoft\Windows\IECompatCache\*"
    "`t `t Path: $LocalAppDataDirectories\Microsoft\Windows\IECompatCache\" | Out-File $fullLogPath -Encoding ASCII -Append

    Write-Host -ForegroundColor Yellow "Clearing $LocalAppDataLabel\Microsoft\Windows\IECompatUaCache\..."
    "Clearing $LocalAppDataLabel\Microsoft\Windows\IECompatUaCache\..." | Out-File $fullLogPath -Encoding ASCII -Append
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$LocalAppDataDirectories\Microsoft\Windows\IECompatUaCache\*"
    "`t `t Path: $LocalAppDataDirectories\Microsoft\Windows\IECompatUaCache\" | Out-File $fullLogPath -Encoding ASCII -Append

    Write-Host -ForegroundColor Yellow "Clearing $LocalAppDataLabel\Microsoft\Windows\IEDownloadHistory\..."
    "Clearing $LocalAppDataLabel\Microsoft\Windows\IEDownloadHistory\..." | Out-File $fullLogPath -Encoding ASCII -Append
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$LocalAppDataDirectories\Microsoft\Windows\IEDownloadHistory\*"
    "`t `t Path: $LocalAppDataDirectories\Microsoft\Windows\IEDownloadHistory\" | Out-File $fullLogPath -Encoding ASCII -Append

    Write-Host -ForegroundColor Yellow "Clearing $LocalAppDataLabel\Microsoft\Windows\INetCache\IE\..."
    "Clearing $LocalAppDataLabel\Microsoft\Windows\INetCache\IE\..." | Out-File $fullLogPath -Encoding ASCII -Append
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$LocalAppDataDirectories\Microsoft\Windows\INetCache\IE\*"
    "`t `t Path: $LocalAppDataDirectories\Microsoft\Windows\INetCache\IE\" | Out-File $fullLogPath -Encoding ASCII -Append

    Write-Host -ForegroundColor Yellow "Clearing $LocalAppDataLabel\Microsoft\Windows\INetCache\Low\..."
    "Clearing $LocalAppDataLabel\Microsoft\Windows\INetCache\Low\..." | Out-File $fullLogPath -Encoding ASCII -Append
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$LocalAppDataDirectories\Microsoft\Windows\INetCache\Low\*"
    "`t `t Path: $LocalAppDataDirectories\Microsoft\Windows\INetCache\Low\" | Out-File $fullLogPath -Encoding ASCII -Append

    Write-Host -ForegroundColor Yellow "Clearing $LocalAppDataLabel\Microsoft\Windows\INetCookies\Low\..."
    "Clearing $LocalAppDataLabel\Microsoft\Windows\INetCookies\Low\..." | Out-File $fullLogPath -Encoding ASCII -Append
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$LocalAppDataDirectories\Microsoft\Windows\INetCookies\Low\*"
    "`t `t Path: $LocalAppDataDirectories\Microsoft\Windows\INetCookies\Low\" | Out-File $fullLogPath -Encoding ASCII -Append

    Write-Host -ForegroundColor Yellow "Clearing $LocalAppDataLabel\Microsoft\Windows\INetCookies\PrivacIE\Low\..."
    "Clearing $LocalAppDataLabel\Microsoft\Windows\INetCookies\PrivacIE\Low\..." | Out-File $fullLogPath -Encoding ASCII -Append
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$LocalAppDataDirectories\Microsoft\INetCookies\PrivacIE\Low\*"
    "`t `t Path: $LocalAppDataDirectories\Microsoft\INetCookies\PrivacIE\Low\" | Out-File $fullLogPath -Encoding ASCII -Append

    Write-Host -ForegroundColor Yellow "Clearing Java cache at C:\Users\$FQDN_User\AppData\LocalLow\Sun\Java\deployment\cache\6.0\..."
    "Clearing Java cache at C:\Users\$FQDN_User\AppData\LocalLow\Sun\Java\deployment\cache\6.0\..." | Out-File $fullLogPath -Encoding ASCII -Append
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "\\$Worktstation\c$\Users\$currentUser\AppData\LocalLow\Sun\Java\deployment\cache\6.0\*"
    "`t `t Path: \\$Worktstation\c$\Users\$currentUser\AppData\LocalLow\Sun\Java\deployment\cache\6.0\" | Out-File $fullLogPath -Encoding ASCII -Append

    Write-Host -ForegroundColor Yellow "Clearing Flash cache at C:\Users\$currentUser\AppData\Roaming\Macromedia\Flash Player\#SharedObjects\..."
    "Clearing Flash cache at C:\Users\$currentUser\AppData\Roaming\Macromedia\Flash Player\#SharedObjects\..." | Out-File $fullLogPath -Encoding ASCII -Append
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "\\$Workstation\c$\Users\$currentUser\AppData\Roaming\Macromedia\Flash Player\#Shared\Objects\*"
    "`t `t Path: \\$Workstation\c$\Users\$currentUser\AppData\Roaming\Macromedia\Flash Player\#Shared\Objects\" | Out-File $fullLogPath -Encoding ASCII -Append

    # Adding in the win7 directories:
    Write-Host -ForegroundColor Yellow "Clearing Chrome cache at C:\Users\$currentUser\AppData\Local\Google\Chrome\User Data\Default\Cache\..."
    "Clearing Chrome cache at C:\Users\$currentUser\AppData\Local\Google\Chrome\User Data\Default\Cache\..." | Out-File $fullLogPath -Encoding ASCII -Append
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "\\$Workstation\c$\Users\$currentUser\AppData\Local\Google\Chrome\User Data\Default\Cache\*"
    "`t `t Path: \\$Workstation\c$\Users\$currentUser\AppData\Local\Google\Chrome\User Data\Default\Cache\" | Out-File $fullLogPath -Encoding ASCII -Append

    Write-Host -ForegroundColor Yellow "Clearing Chrome application cache at C:\Users\$currentUser\AppData\Local\Google\Chrome\User Data\Default\Application Cache\Cache\..."
    "Clearing Chrome application cache at C:\Users\$currentUser\AppData\Local\Google\Chrome\User Data\Default\Application Cache\Cache\..." | Out-File $fullLogPath -Encoding ASCII -Append
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "\\$Workstation\c$\Users\$currentUser\AppData\Local\Google\Chrome\User Data\Default\Application Cache\Cache\*"
    "`t `t Path: \\$Workstation\c$\Users\$currentUser\AppData\Local\Google\Chrome\User Data\Default\Application Cache\Cache\" | Out-File $fullLogPath -Encoding ASCII -Append

    Write-Host -ForegroundColor Yellow "Clearing $LocalAppDataLabel\Microsoft\Windows\Temporary Internet Files\Content.IE5\"
    "Clearing $LocalAppDataLabel\Microsoft\Windows\Temporary Internet Files\Content.IE5\" | Out-File $fullLogPath -Encoding ASCII -Append
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "\\$Workstation\c$\Users\$currentUser\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\*"
    "`t `t Path: \\$Workstation\c$\Users\$currentUser\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\" | Out-File $fullLogPath -Encoding ASCII -Append

    Write-Host -ForegroundColor Yellow "Clearing $LocalAppDataLabel\Microsoft\Windows\Temporary Internet Files\Content.Outlook\"
    "Clearing $LocalAppDataLabel\Microsoft\Windows\Temporary Internet Files\Content.Outlook\" | Out-File $fullLogPath -Encoding ASCII -Append
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "\\$Workstation\c$\Users\$currentUser\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook\*"
    "`t `t Path: \\$Workstation\c$\Users\$currentUser\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook\" | Out-File $fullLogPath -Encoding ASCII -Append

    Write-Host -ForegroundColor Yellow "Clearing $LocalAppDataLabel\Microsoft\Windows\Temporary Internet Files\Low\Content.IE5\"
    "Clearing $LocalAppDataLabel\Microsoft\Windows\Temporary Internet Files\Low\Content.IE5\" | Out-File $fullLogPath -Encoding ASCII -Append
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "\\$Workstation\c$\Users\$currentUser\AppData\Local\Microsoft\Windows\Temporary Internet Files\Low\Content.IE5\*"
    "`t `t Path: \\$Workstation\c$\Users\$currentUser\AppData\Local\Microsoft\Windows\Temporary Internet Files\Low\Content.IE5\" | Out-File $fullLogPath -Encoding ASCII -Append

    "" | Out-File $fullLogPath -Encoding ASCII -Append
    "# # # # # # # # # # # # # # # # # # # #" | Out-File $fullLogPath -Encoding ASCII -Append
    "" | Out-File $fullLogPath -Encoding ASCII -Append
} else {
    Write-Host ""
    Write-Host -ForegroundColor Red "The workstation $Workstation is not accessible. Please correct the host or try again later."
    "Workstation is in accessible." | Out-File $fullLogPath -Encoding ASCII -Append
}

Stop-Transcript