# Impersonation
## ARP Spoofing

A Python-based ARP cache poisoning tool for demonstrating MITM (Man-in-the-Middle) attacks between two network devices.

### Current Implementation 
- Bidirectional ARP spoofing
- Automatic ARP table restoration on exit (Ctrl+C)
- Configurable target IP addresses
- 2-second refresh interval

### Usage
1. **Start monitoring** (new terminal):
sudo tcpdump -i eth0 -nnv "host 192.168.1.16 and host 192.168.1.23"


2. **Run the ARP spoofer**:
sudo python3 arp_spoof.py


3. **Verify ARP table changes** on target devices:
On nano1 (192.168.1.16):
arp -n | grep 192.168.1.23

On agx1 (192.168.1.23):
arp -n | grep 192.168.1.16


### Configuration
Edit these variables in the script:
iface = "eth0" # Network interface
nano1_ip = "192.168.1.16" # First target IP
agx1_ip = "192.168.1.23" # Second target I

### Key Commands
| Command | Purpose |
|---------|---------|
| `sudo tcpdump -i eth0 -nnv "host 192.168.1.16 and host 192.168.1.23"` | Monitor target traffic |
| `arp -n` | Check ARP table entries |
| `echo 1 > /proc/sys/net/ipv4/ip_forward` | Enable IP forwarding |

### Troubleshooting
1. **Permission errors?**
   - Run with `sudo`
   - Ensure no other ARP tools are running

2. **MAC discovery failures?**
- Ensure targets are on same VLAN
- Check physical connectivity