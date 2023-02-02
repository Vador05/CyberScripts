Import-Module ActiveDirectory

# Variables
$domain = "example.com"
$ouPath = "OU=GPO,DC=example,DC=com"
$guid = "11111111-2222-3333-4444-555555555555"

# Create a user called "Admin" in Active Directory
New-ADUser -Name "Admin" -SamAccountName "Admin" -UserPrincipalName "Admin@$domain" -Enabled $true -PasswordNeverExpires $true -ChangePasswordAtLogon $false

# Create a GPO for the warning message
New-GPO -Name "LoginWarning"
Set-GPO -Name "LoginWarning" -UserOwner "Admin"

# Add a script to the GPO to write the warning message to the system logs
New-Item -Path "\\$domain\SysVol\$domain\Policies\$guid\User\Scripts\Logon" -ItemType Directory
Set-Content -Path "\\$domain\SysVol\$domain\Policies\$guid\User\Scripts\Logon\warning.ps1" -Value "Write-EventLog -LogName System -Source 'Security' -EventId 12345 -Message 'WARNING: Malicious activity detected from [ip]'"
Add-GPLogonScript -GPName "LoginWarning" -ScriptPath "\\$domain\SysVol\$domain\Policies\$guid\User\Scripts\Logon\warning.ps1"

# Link the GPO to the "Admin" user
New-ADOrganizationalUnit -Name "GPO" -Path $ouPath
Get-ADOrganizationalUnit -Filter {DistinguishedName -eq $ouPath} | New-ADGroup -Name "GPOAdmin" -GroupScope Global -GroupCategory Security
Get-ADGroup -Filter {Name -eq "GPOAdmin"} | Add-ADPrincipalGroupMembership -Member "Admin"
Get-ADOrganizationalUnit -Filter {DistinguishedName -eq $ouPath} | Set-GPInheritance -Target "GPOAdmin"
