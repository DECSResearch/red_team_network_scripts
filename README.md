# Scripts Status

## Functioning Scripts

| Script | Classification | Description | Last Updated | Documentation |
|--------|---------------|-------------|--------------|---------------|
| [arp_spoof.py](src/impersonation/arp_spoof.py) | Impersonation | Bidirectional ARP cache poisoning tool | 2025-02-24 | [README](#arp-spoofing) |
| [brute_charset.py](src/flooding/bruteforce_char.py) | Flooding | Alphabet-based brute force (a-zA-Z0-9!@#) | 2025-02-19 | [README](#alphabet-based-brute-force) |
| [dict_attack.py](src/flooding/bruteforce_dict.py) | Flooding | Dictionary attack with Top 150k passwords | 2025-02-19 | [README](#ssh-dictionary-attack-tool) |
| [arp_blackout.py](src/impersonation/arp_blackout.py) | Impersonation | Advanced ARP cache poisoning | 2025-03-07| [README](#arp-blackout-attack-tool)|
| [FDIA.py](src/Injection/FDIA.py) | Injection | TCP/ModBus protocol data manipulation tool | 2025-03-10 | [README](#false-data-injection-attack) |
| [arp_eavesdrop.py](src/impersonation/arp_eavesdrop.py) | Impersonation | Passive network traffic sniffer | 2025-03-10 | [README](#arp-eavesdropping-attack) |

## In Progress

| Script | Description | Progress | ETA |
|--------|-------------|----------|-----|
| [keylogger.py](add/keylogger.py) | Cross-platform input capture module | _ | _ |
| [distributed_bruteforce.py](pplx://action/followup) | - |  |  |
| [ddos_botnet.py](pplx://action/followup) | Multi-threaded flood with IP spoofing |  |  |
| [dos.py](pplx://action/followup) | ICMP flood with IP spoofing |  |  |
| [Phishing](pplx://action/followup) | _ |  |  |
| [arp_storm_targeted.py](pplx://action/followup) | Flood packets of ARP requests to disrupt the device communications |  |  |
| [arp_storm_network.py](pplx://action/followup) | Flood packets of ARP requests to disrupt the network communications |  |  |
| [reverse_shell.py](pplx://action/followup) | ADD |  |  |
| [RCE.py](pplx://action/followup) | Remote Code Execution |  |  |


> **Legend**  
> **Last Updated**: Date of last successful test  
> **ETA**: Estimated completion date for current sprint


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

### File Requirements
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
- NFqueue unbind


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

## ARP Blackout Attack Tool

A network disruption tool that performs ARP cache poisoning to isolate target devices from the local network. Built with Scapy for educational/penetration testing purposes.

### Key Features 

- **Network Discovery**  
  Auto-scans subnet to map active IP/MAC pairs
- **MAC Randomization & Unique MAC Detection**  
  Generates vendor-plausible spoofed addresses using common OUIs and ensures uniqueness by checking against the discovered devices.
- **Bidirectional Spoofing**  
  Poisons ARP caches of all network devices toward target.
- **Repeat Broadcast**  
  Continuously sends spoofed ARP packets at configurable intervals to maintain ARP cache poisoning.
- **Self-Healing Network**  
  Automatic ARP table restoration on exit (Ctrl+C)
- **Stealth Mode**  
  Randomized attack intervals and persistent spoofing

### Usage
1. **Install dependencies** (Scapy required):  
`pip3 install scapy`
2. **Run Attack**
   - Basic Attack:
     `sudo python3 arp_blackout.py 192.168.1.15`
   - Advanced Options:
     Custom interface and 15-second interval:
     `sudo python3 arp_blackout.py 192.168.1.25 -i wlan0 -t 15`
3. **Check target's ARP table changes**:  
`arp -n | grep 192`
4. **Monitor network traffic during attack**:
`sudo tcpdump -i eth0 arp -vv`

### Command Options
| Option | Description | Default |
|--------|-------------|---------|
| `target` | Target IP address | *Required* |
| `-i INTERFACE` | Network interface | `eth0` |
| `-t SECONDS` | Spoofing interval | `10` |


### Technical Enhancements

**Unique MAC Detection**
-  Avoid generating a spoofed MAC address that's already present on the network.
  
**Repeat Broadcast**
- Ensure persistent ARP poisoning by re-sending spoofed ARP packets at regular intervals.

### Post-Attack Validation
1. Confirm target regains network connectivity
2. Verify original MAC addresses reappear in ARP tables

### Troubleshooting
**Common Issues**:
- `Target not found`: Ensure device is online (`ping -c 4 target_ip`)
- `Permission denied`: Run with `sudo` privileges
- `Spoofing ineffective`: Enable IP forwarding (`echo 1 > /proc/sys/net/ipv4/ip_forward`)

## ARP Eavesdropping Attack

A Python-based network traffic interceptor that combines ARP spoofing with packet capture capabilities. This tool allows for real-time MITM (Man-in-the-Middle) positioning to passively collect and save all traffic between two network endpoints for later analysis.

### Current Implementation

- **Bidirectional ARP Spoofing** to intercept traffic between two hosts
- **Concurrent Packet Capture** with multi-threaded operation
- **PCAP Export** for offline analysis with Wireshark or other tools
- **Automatic Network Configuration** of IP forwarding and iptables
- **Clean Network Restoration** upon exit
- **Flexible Timing Controls** for periodic ARP packet refreshes

### Usage
1. **Install dependencies** (Scapy required):  `pip3 install scapy`
2. **Basic usage**:`sudo python3 arp_eavesdrop.py 192.168.1.15 192.168.1.23`
3. **Custom interface and output file**:`sudo python3 arp_eavesdrop.py 192.168.1.15 192.168.1.23 -i wlan0 -o custom_capture.pcap`

4. **With recursive ARP spoofing every 5 seconds**:` sudo python3 arp_eavesdrop.py 192.168.1.15 192.168.1.23 -r 5`

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `target1` | First target IP address (required) | - |
| `target2` | Second target IP address (required) | - |
| `-i/--interface` | Network interface to use | eth0 |
| `-r/--recursive` | Seconds between ARP refreshes (0=once) | 0 |
| `-o/--output` | Output PCAP filename | captured_traffic.pcap |

### Technical Operation

1. **Network Preparation**:
   - Enables IP forwarding in Linux kernel
   - Configures iptables to allow forwarded traffic

2. **ARP Cache Poisoning**:
   - Sends crafted ARP packets to both targets
   - Convinces each target that the attacker's MAC is associated with the other target's IP
   - Optionally refreshes ARP cache periodically to maintain the attack

3. **Traffic Capture**:
   - Launches a separate thread for packet sniffing
   - Collects all packets passing through the attack machine
   - Stores packets in memory until termination
   - Writes collected packets to disk in PCAP format upon exit

4. **Restoration**:
   - Sends corrective ARP packets to restore normal network operation
   - Removes iptables rules
   - Disables IP forwarding

### Troubleshooting

1. **MAC Address Discovery Failure**
   - Ensure targets are online and responding to ARP
   - Check that the specified interface has network access
   - Try increasing ARP timeout with a code modification

2. **No Traffic Capture**
   - Verify ARP spoofing success with `arp -a` on targets
   - Ensure IP forwarding is enabled: `cat /proc/sys/net/ipv4/ip_forward`
   - Check iptables rules: `sudo iptables -L FORWARD -v`

3. **Permission Errors**
   - Run with sudo privileges
   - Check output file path permissions


Analysis of captured traffic can be performed with tools like Wireshark, Tshark, or NetworkMiner.


****
# Injection

## False Data Injection Attack

A Python-based FDIA (False Data Injection Attack) tool designed to intercept and modify TCP/ModBus protocol data packets in real-time. Built to demonstrate how attackers can manipulate critical measurement values in industrial systems while remaining undetected.

### Current Implementation

- **Multiple Modification Patterns** with 6 mathematical models:
  - Static (constant offset)
  - Dynamic (randomly selected function)
  - Gaussian distribution
  - Sigmoid function
  - Sinusoidal wave
  - Exponential curve
  - Pulse/step change
  - Polynomial (quadratic)
- **Packet Interception** via NetfilterQueue
- **Seamless Packet Modification** with automatic checksum recalculation
- **Automatic IPTables Management** for traffic redirection
- **Intelligent Error Handling** with cleanup on exceptions
- **Debug Mode** for real-time attack monitoring
- **Requires ARP Spoofing** to be running in parallel (uses `arp_spoof.py`)

### Usage

1. **Install dependencies**:`pip3 install scapy netfilterqueue numpy`

2. **Start ARP spoofing in a separate terminal**:`sudo python3 arp_spoof.py 192.168.1.15 192.168.1.23 -i eth0 -r 5`

3. **Execute the FDIA attack**:`sudo python3 FDIA.py 192.168.1.15 -p 30502 -f gaussian`

4. **Monitor with debug mode**:`sudo python3 FDIA.py 192.168.1.15 -p 30502 -f dynamic -d`

5. **Check Kafka for frequency changes**:
   Monitor the Kafka stream to observe frequency value modifications in real-time.

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `target` | Target IP address (required) | - |
| `-p/--port` | Target port number | 30502 |
| `-f/--frequency` | Modification pattern | static |
| `-d/--debug` | Enable debug output | False |

### Available Frequency Patterns

| Pattern | Description | Effect |
|---------|-------------|--------|
| `static` | Constant offset (+30Hz) | Fixed manipulation |
| `dynamic` | Randomly selected function | Unpredictable changes |
| `gaussian` | Bell curve distribution | Gradual rise and fall |
| `sigmoid` | S-shaped curve | Smooth transition |
| `sin` | Sine wave | Cyclical variation |
| `exponential` | Exponential decay | Rapid drop-off |
| `pulse` | Step function | Sudden jump |
| `polynomial` | Quadratic curve | Parabolic change |

### Troubleshooting

1. **NetfilterQueue Binding Errors**
   - Verify no other applications are using queue 1
   - Run: `sudo pkill -f NFQUEUE` to clear existing queue bindings
   - Install required dependencies:
     ```
     sudo apt-get install build-essential python3-dev libnetfilter-queue-dev libnfnetlink-dev
     sudo apt install libnfnetlink-dev libnetfilter-queue-dev
     pip3 install nfqp3
     pip3 install cython
     git clone https://github.com/oremanj/python-netfilterqueue
     cd python-netfilterqueue
     pip3 install .
     ```

2. **Queue Conflict**
   - If "Failed to create queue" error appears:
     ```
     sudo rm /run/xtables.lock  # Clear stale lock
     sudo pkill -f NFQUEUE      # Kill existing queue users
     ```

3. **Missing Traffic**
   - Confirm ARP spoofing is active and successful
   - Verify target IP and port are correct
   - Check iptables rules: `sudo iptables -L FORWARD -v`

4. **No Effect on Target**
   - Ensure target is using the expected protocol
   - Check if target validates input values
   - Try different frequency pattern with larger magnitude

### Operational Notes

1. **Attack flow**:
   - ARP spoofing redirects traffic through attacker
   - FDIA intercepts specific packets
   - Payload values modified according to pattern
   - Modified packets forwarded to destination

2. This attack specifically targets register 101 with frequency values, but can be modified for other industrial protocols and parameters.

3. Always restore network state after testing by properly terminating both the ARP spoofing and FDIA scripts with Ctrl+C.

