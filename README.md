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
### Uninstall
```bash
sudo rmmod kdai
