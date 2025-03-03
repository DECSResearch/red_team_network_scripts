# Scripts Status

## 🟢 Functioning Scripts

| Script | Description | Last Updated | Documentation |
|--------|-------------|--------------|---------------|
| [arp_spoof.py](src/impersonation/arp_spoof.py) | Bidirectional ARP cache poisoning tool | 2025-02-24 | [README](#arp-spoofing) |
| [brute_charset.py](src/flooding/bruteforce_char.py) | Alphabet-based brute force (a-zA-Z0-9!@#) | 2025-02-19 | [README](#alphabet-based-brute-force) |
| [dict_attack.py](src/flooding/bruteforce_dict.py) | Dictionary attack with Top 150k passwords | 2025-02-19 | [README](#ssh-dictionary-attack-tool) |


## 🟡 In Progress

| Script | Description | Progress | ETA |
|--------|-------------|----------|-----|
| [keylogger.py](add/keylogger.py) | Cross-platform input capture module | _ | _ |
| [distributed_bruteforce.py](pplx://action/followup) | WordPress credential brute-forcing via hijacked browsers |  |  |
| [ddos_botnet.py](pplx://action/followup) | Multi-threaded HTTP flood with IP spoofing |  |  |
| [dos.py](pplx://action/followup) | HTTP flood with IP spoofing |  |  |
| [Phishing](pplx://action/followup) | _ |  |  |
| [FIDA](pplx://action/followup) | FDIA | HK | 2025-02-24 |
| [arp_storm_targeted.py](pplx://action/followup) | Flood packets of ARP requests to disrupt the device communications | HK | 2025-02-24 |
| [arp_storm_network.py](pplx://action/followup) | Flood packets of ARP requests to disrupt the network communications |  |  |
| [arp_eavesdrop.py](pplx://action/followup) | Passive Network packet collection |  |  |
| [reverse_shell.py](pplx://action/followup) | ADD |  |  |
| [RCE.py](pplx://action/followup) | Remote Code Execution |  |  |

## Key
- 🟢 = Stable/Production Ready
- 🟡 = Active Development
- 🔴 = Broken/Needs Fixing
- ⚫ = Deprecated

> **Legend**  
> **Last Updated**: Date of last successful test  
> **ETA**: Estimated completion date for current sprint

## Attack Classification

### Flooding Attacks  
- **brute_charset.py**: Alphabet-based credential brute-forcing  
- **dict_attack.py**: Dictionary-based password attacks  
- **distributed_bruteforce.py**: Distributed credential cracking  
- **ddos_botnet.py**: Coordinated HTTP flood attacks  
- **dos.py**: Denial-of-service through HTTP flooding  
- **apr_flood.py**: ARP request flooding  

### Impersonation Attacks  
- **arp_spoof.py**: ARP cache poisoning/MITM  
- **Phishing**: Identity deception attacks  

### Injection Attacks  
- **keylogger.py**: System input interception  
- **FIDA**: False data injection attacks  

## Classification Rationale

Based on standard network attack taxonomy:

- **Flooding**: Focuses on resource exhaustion through traffic/request overload  
- **Impersonation**: Utilizes identity deception and MITM techniques  
- **Injection**: Involves malicious data insertion or system interference



# Flooding

## Alphabet based brute force
A python based SSH credential brute-forcing using character combinations.

### Current Implementation
- CLI configuration via argparse for IP/user inputs
- Full printable ASCII character set (100 chars)
- Progressive length attempts (1-13 characters)
- Visual progress tracking with `tqdm`
- Automatic retry mechanism
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

### Configuration Options
| Parameter | Default | Description |
|-----------|---------|-------------|
| `min_length` | 1 | Minimum password segments |
| `max_length` | 13 | Maximum password combinations |
| `timeout` | 1s | SSH connection timeout |
| `retry_delay` | 2s | Network error cooldown |

## Performance Notes
- Theoretical attempt count: 2.27e25 combinations (for 13 chars)
- Practical limitations:
- Network latency impacts speed
- SSH handshake overhead
- Lockout policies (not handled)
- Hardware limitations


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


## SSH Dictionary Attack Tool

A multi-process Python script for performing high-speed dictionary attacks against SSH services using password lists.

### Current Implementation
- **Multi-core processing** using `multiprocessing.Pool`
- **Dictionary-based attacks** with configurable wordlists
- **Automatic retry system** for network errors
- **SSH connection recycling** (prevents resource exhaustion)
- **Progress visualization** with `tqdm` integration
- **Clean exit handling** via `finally` clause

### 📁 File Requirements
- `InsidePro.dic` password dictionary in working directory
- Custom wordlist support (modify `alnum` loading)

### Usage

1. **Install dependencies**: `pip3 install paramiko tqdm`

2. **Run attack** (4-core example):`python3 dict_attack.py 192.168.1.25 admin`

3. **Monitor output**:
[*] Starting Dictionary attack on 192.168.1.25 with username admin
Brute Force Progress: 12%|██▏ | 1200/10000 [00:45<05:12, 26.21it/s]


### Configuration Options
| Parameter | Default | Description |
|-----------|---------|-------------|
| `timeout` | 1s | SSH connection timeout |
| `retry_delay` | 2s | Network error cooldown |


**Flow Explanation**  
1. **Dictionary Loading**: Reads `InsidePro.dic` containing password candidates  
2. **List Generation**: Creates attack permutations from dictionary entries  
3. **Parallel Processing**: Distributes workload across all CPU cores  
4. **Connection Phase**: Each worker performs:  
   - SSH handshake with timeout  
   - Authentication attempt  
   - Error classification (retry vs discard)  
5. **Result Handling**: Successful finds terminate all workers immediately  


### Troubleshooting
**Dictionary Load Failures**  
➔ Verify `InsidePro.dic` exists in execution directory  
➔ Check file read permissions: `ls -l InsidePro.dic`

**Performance Issues**  
➔ Limit CPU cores: `with Pool(processes=2) as pool`  
➔ Disable progress bar: remove `tqdm` wrapper

**Connectivity Problems**  
nc -zvw3 <TARGET_IP> 22 # Verify SSH port accessibility
ping <TARGET_IP> # Check basic connectivity

text

### Operational Notes
1. **Wordlist Formatting**  
   Ensure dictionary file uses UNIX line endings (LF)  
   Remove empty lines: `sed -i '/^$/d' InsidePro.dic`

2. **Performance Tuning**  
   Optimal pool size = CPU cores - 1  
   For 8-core CPU: `Pool(processes=7)`


### Expected Performance
| CPU Cores | Passwords/Sec | 10k-wordlist Time |
|-----------|---------------|-------------------|
| 2         | 18-22         | ~9-11 mins        |
| 4         | 35-40         | ~4-5 mins         |
| 8         | 65-75         | ~2-3 mins         |  
*Based on 100Mbps network connection to target*

****

# Impersonation
## ARP Spoofing

A Python-based ARP cache poisoning tool for demonstrating MITM (Man-in-the-Middle) attacks between two network devices.

### Current Implementation 
- CLI configuration with argparse for targets/interface
- Bidirectional ARP spoofing
- Configurable spoofing intervals
- Automatic ARP table restoration on exit (Ctrl+C)
- IP forwarding automation (enables/disables automatically)
- Iptables rule management for traffic forwarding
- Configurable network interface and target IPs


### Usage
1. **Start monitoring** (new terminal):
```sudo tcpdump -i eth0 -nnv "host 192.168.1.16 and host 192.168.1.23"```

2. **Run the ARP spoofer**:
```sudo python3 arp_spoof.py 192.168.1.16 192.168.1.23 -i eth0```

*Persistent spoofing* (resend every 5 seconds)
```sudo python3 arp_spoof.py 192.168.1.16 192.168.1.23 -i eth0 -r 5```


3. **Verify ARP table changes** on target devices:
On target_1 (192.168.1.16):
```arp -n | grep 192.168.1.23```

On target_2 (192.168.1.23):
```arp -n | grep 192.168.1.16```

### Automatic Management
The script now handles these automatically:
- Enables/disables IP forwarding (`net.ipv4.ip_forward`)
- Adds/removes iptables rules for ICMP/TCP forwarding
- Restores original MAC addresses on exit


#### Command Options
| Option | Description |
|--------|-------------|
| `target1` | IP address of first target (required) |
| `target2` | IP address of second target (required) |
| `-i INTERFACE` | Network interface (default: eth0) |
| `-r SECONDS` | Resend ARP spoofs at interval (0=once, default:0) |

### Troubleshooting
1. **Permission errors?**
- Run with `sudo`
- Ensure no other ARP tools are running

2. **MAC discovery failures?**
- Ensure targets are on same VLAN
- Check physical connectivity

3. **Traffic not forwarding?**
- Confirm script output shows enabled IP forwarding
- Check iptables rules exist: `sudo iptables -L FORWARD -v`
- Verify target IPs are active (`ping` test)

4. **ARP tables not restoring?**
- Manually run restoration command: `arp -s TARGET_IP TARGET_MAC`

5. **Traffic stops forwarding after time?**  
→ Combine `-r 5` with persistent iptables rules:  
`sudo iptables-save > /etc/iptables/rules.v4`

 ### Advanced Use
For long sessions, consider creating a systemd service to maintain spoofing after disconnections. Add these iptables rules permanently with: `sudo iptables-save > /etc/iptables/rules.v4`
