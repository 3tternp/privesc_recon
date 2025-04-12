# PrivEsc-Recon.ps1
# PowerShell tool for privilege escalation enumeration (lab use only)

Write-Host "==== Privilege Escalation Recon Tool ====" -ForegroundColor Cyan

# 1. Check current user and group memberships
Write-Host "`n[+] Current User and Groups:"
whoami /all

# 2. UAC Status
Write-Host "`n[+] UAC Settings:"
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System | 
  Select-Object ConsentPromptBehaviorAdmin, PromptOnSecureDesktop

# 3. Check AlwaysInstallElevated setting (dangerous if enabled)
Write-Host "`n[+] AlwaysInstallElevated Check:"
$ae1 = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue
$ae2 = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue
"HKCU: $($ae1.AlwaysInstallElevated)"
"HKLM: $($ae2.AlwaysInstallElevated)"

# 4. Search for unquoted service paths
Write-Host "`n[+] Unquoted Service Paths:"
Get-WmiObject win32_service | Where-Object {
    $_.PathName -match " " -and $_.PathName -notmatch '^"'
} | Select-Object Name, PathName

# 5. Search for folders writable by user in system paths
Write-Host "`n[+] Writable Folders in System Paths:"
$paths = "C:\Program Files\", "C:\Program Files (x86)\", "C:\Windows\System32"
foreach ($p in $paths) {
    try {
        Get-ChildItem $p -Recurse -ErrorAction SilentlyContinue | Where-Object {
            ($_ -is [System.IO.DirectoryInfo]) -and
            (Test-Path $_.FullName -PathType Container) -and
            (Get-Acl $_.FullName).AccessToString -match "Everyone Allow  Modify"
        } | Select-Object FullName
    } catch {}
}

# 6. Recent SYSTEM executables from event logs
Write-Host "`n[+] Recent SYSTEM Executions:"
Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4688} -MaxEvents 50 | Where-Object {
    $_.Message -match "SYSTEM"
} | Select-Object -First 10 | Format-Table TimeCreated, Message -Wrap

Write-Host "`n[*] Enumeration complete." -ForegroundColor Green
