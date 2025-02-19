# Scripts Status

## 🟢 Functioning Scripts

| Script | Description | Last Updated | Documentation |
|--------|-------------|--------------|---------------|
| [arp_spoof.py](src/impersonation/arp_spoof.py) | Bidirectional ARP cache poisoning tool | 2024-02-19 | [README](#arp-spoofing) |
| [brute_charset.py](src/flooding/bruteforce_char.py) | Alphabet-based brute force (a-zA-Z0-9!@#) | 2025-02-19 | [README](#brute-force) |
| [dict_attack.py](src/flooding/bruteforce_dict.py) | Dictionary attack with Top 150k passwords | 2025-02-19 | [Docs](#dict_attacks) |


## 🟡 In Progress

| Script | Description | Progress | ETA |
|--------|-------------|----------|-----|
| [keylogger.py](add/keylogger.py) | Cross-platform input capture module | _ | _ |
| [distributed_bruteforce.py](pplx://action/followup) | WordPress credential brute-forcing via hijacked browsers |  |  |
| [ddos_botnet.py](pplx://action/followup) | Multi-threaded HTTP flood with IP spoofing |  |  |
| [dos.py](pplx://action/followup) | HTTP flood with IP spoofing |  |  |
| [Phishing](pplx://action/followup) | _ |  |  |
| [FIDA](pplx://action/followup) | FDIA |  |  |

## Key
- 🟢 = Stable/Production Ready
- 🟡 = Active Development
- 🔴 = Broken/Needs Fixing
- ⚫ = Deprecated

> **Legend**  
> **Last Updated**: Date of last successful test  
> **ETA**: Estimated completion date for current sprint

# Flooding

## Alphabet-based brute force
A python based SSH credential brute-forcing using character combinations.

### Current Implementation
- CLI configuration via argparse for IP/user inputs
- Full printable ASCII character set (100 chars)
- Progressive length attempts (1-13 characters)
- Visual progress tracking with `tqdm`
- Network error recovery system
- 1-second SSH connection timeout
- 2-second retry delay on exceptions

### Usage
1. **Install dependencies**: `pip3 install paramiko tqdm`

2. **Execute brute force attack**: `python3 bruteforce.py <target_ip> <username>`

Example: `python3 bruteforce.py 192.168.1.45 admin`

3. **Monitor progress**:
[*] Starting brute force attack on 192.168.1.45 with username admin
Brute Force Progress: 0%|           | 0/100 [00:00<?, ?it/s]


### Troubleshooting
1. **Paramiko installation failures?**
- Update pip: `python3 -m pip install --upgrade pip`
- Install development tools: `sudo apt install python3-dev libffi-dev`

2. **Connection timeouts?**
- Verify target SSH port accessibility: `nc -zv <IP> 22`
- Ping device
- Check local firewall rules

3. **High failure rate?**
- Confirm username validity first
- Check target's failed attempt thresholds
- Consider narrowing character set in code

4. **Performance issues?**
- Remove progress bar (`tqdm`) for raw speed
- Increase timeout value in `ssh_connect()`


****

# Impersonation
## ARP Spoofing

A Python-based ARP cache poisoning tool for demonstrating MITM (Man-in-the-Middle) attacks between two network devices.

### Current Implementation 
- CLI configuration with argparse for targets/interface
- Bidirectional ARP spoofing
- Automatic ARP table restoration on exit (Ctrl+C)
- Configurable target IP addresses
- 2-second refresh interval

### Usage
1. **Start monitoring** (new terminal):
```sudo tcpdump -i eth0 -nnv "host 192.168.1.16 and host 192.168.1.23"```
2. **Enable IP forwarding)** (if not already set):
```sudo sysctl -w net.ipv4.ip_forward=1``` # Temporary enable
For persistence: add 'net.ipv4.ip_forward=1' to /etc/sysctl.conf

4. **Run the ARP spoofer**:
```sudo python3 arp_spoof.py 192.168.1.16 192.168.1.23 -i eth0```


5. **Verify ARP table changes** on target devices:
On target_1 (192.168.1.16):
```arp -n | grep 192.168.1.23```

On target_2 (192.168.1.23):
```arp -n | grep 192.168.1.16```


### Key Commands
| Command | Purpose |
|---------|---------|
| `sudo tcpdump -i eth0 -nnv "host 192.168.1.16 and host 192.168.1.23"` | Monitor target traffic |
| `arp -n` | Check ARP table entries |
| `sysctl -w net.ipv4.ip_forward=1` | Enable persistent packet forwarding |

### Troubleshooting
1. **Permission errors?**
- Run with `sudo`
- Ensure no other ARP tools are running

2. **MAC discovery failures?**
- Ensure targets are on same VLAN
- Check physical connectivity

3. **No traffic visible?**
- Confirm IP forwarding is enabled:
     ```sudo sysctl -w net.ipv4.ip_forward=1```
- Check correct network interface
- Verify target IPs are active (`ping` test)


 For long sessions, consider adding a systemd service to maintain spoofing after disconnections.
