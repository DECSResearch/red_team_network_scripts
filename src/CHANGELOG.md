## Version 0.03
Fixed iptables rule deletion syntax by removing erroneous -I flag in removal commands.
Ensures rule removal matches original insertion parameters for proper firewall state restoration.
Recurrent spoofing - New `recursive` argument (seconds between ARP resends)  

## Version 0.0.2
ARP spoof working, added ip forwarding and ip_table change feature
**Changes from previous version:**
- Removed manual IP forwarding steps (now automated)
- Added iptables rule management documentation
- Updated troubleshooting for new features
- Simplified usage instructions
- Removed 2-second interval mention (now single-shot with sleep)

## Version 0.0.1
ARP table is being spoofed
BUT *ARP not sending packets*

Brute force Char-Based is not on Multi-core processing, Max length of chars is fixed to 13 (Hard Coded).

Brute force Dictionary Attack Works perfect, uses InsidePro.dic (Hardcoded)




