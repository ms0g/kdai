# kdai
A LKM(Loadable Kernel Module) for detection and prevention of [ARP Poisoning Attack](https://en.wikipedia.org/wiki/ARP_spoofing). 

kdai intercepts all ARP requests and responses.Each of these intercepted packets is verified for valid MAC address to IP address bindings before the local ARP cache is updated. Invalid ARP packets are dropped.

Determining the validity of ARP packet is based on a cross-checking of ARP cache and a valid MAC address to IP address bindings stored in the DHCP snooping table which is built at runtime.

### Prerequisites
+ [GCC](http://gcc.gnu.org "GCC home") (>= 5.4.0)
### Building
```bash
make
```
### Install
```bash
sudo insmod kdai.ko
```
### Test
```bash
$ dmesg | tail -5
[80073.746601] kdai:  DHCP Thread Created Successfully...
[80145.589597] kdai:  DHCPACK of 192.168.1.51
[80160.701525] kdai:  Invalid ARP request from 08:00:27:21:04:c5
[80178.871986] kdai:  ARP spoofing detected on enp0s8 from 08:00:27:21:04:c5
[80550.748553] kdai:  DHCPACK of 192.168.1.42
```
### Uninstall
```bash
sudo rmmod kdai
