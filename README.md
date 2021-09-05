# mitm-with-scapy

## Description
This script is alternative to the Ettercap (Man-in-the-Middle tool). Scapy is the main tool used to dissect the packet and perform the ARP spoofing attack. However, scapy  is not enough to modify the packet and send it to the destination. Thus, netfilterqueue was used to queue the incoming packets and release them after modifications. Checksums are removed in order to be recalculated by scapy. For eveything to work smoothly, it is important to set ip forwarding and firewall rules. 

> Note: to trick more hosts, script has to be executed more than once with the following modification:
> ```nfqueue.bind(n, modifyPacket)``` where n is the number of runs, e.g. 2 for second execution of the script.


## References
https://0xbharath.github.io/art-of-packet-crafting-with-scapy/network_attacks/arp_spoofing/index.html
https://byt3bl33d3r.github.io/using-nfqueue-with-python-the-right-way.html
