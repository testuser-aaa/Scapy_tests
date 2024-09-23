#!/usr/bin/env python3
from scapy.all import *
import argparse

def get_arguments():
    parser = argparse.ArgumentParser(description="ip address to scan for")
    parser.add_argument('-i',dest='iface',type=str,help="enter the interface aka dev", required=True)
    #parser.add_argument('-d',dest='ip_addr',type=str,help="enter ip of the target ",required=True)
    
    args=parser.parse_args()
    return args

def get_mac(ip,iface):
    clients_list=[]
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), iface=iface,timeout=1,verbose=False)
    for i in ans:
        client_dict={'ip':i[1].psrc,'mac':i[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list[0]['mac']

def prn(packet):
    if packet.haslayer(ARP) and packet[ARP].op==2:
        try:
            real_mac=get_mac(packet[ARP].psrc,i)
            response_mac=packet[ARP].hwsrc
            if real_mac !=response_mac:
                print("arp_spoof detect!")
        except:
            pass

def sniffp(iface):
    sniff(iface=iface,prn=prn,store=False)

if __name__=='__main__':
    args = get_arguments()
    i=args.iface
    sniffp(i)
