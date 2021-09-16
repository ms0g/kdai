# kdai
A LKM(Loadable Kernel Module) for detection and prevention of ARP Poisoning Attack. The module builds a DHCP snooping table that includes mapping IP address and MAC pair on runtime, then performs a cross-checking of ARP cache and the table. If any mismatch, drops the packet.
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
[80160.701525] kdai:  Not valid ARP request from 08:00:27:21:04:c5
[80178.871986] kdai:  ARP spoofing detected on enp0s8 from 08:00:27:21:04:c5
[80550.748553] kdai:  DHCPACK of 192.168.1.42
```
### Uninstall
```bash
sudo rmmod kdai
