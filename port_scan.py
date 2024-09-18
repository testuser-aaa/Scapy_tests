#!/usr/bin/env python3
#немного докрученый сканер портов из книги Python for Cybersecurity.Using Python for Cyber Offense and Defense / Howard E. Poston III
#по умолчанию сканирует по малому списку
import re
from scapy.all import *
import argparse
from colorama import Fore

big = [20, 21, 22, 23, 25, 42, 43, 53, 67, 69, 80, 110, 115, 123, 137, 138, 139, 143, 161, 179, 443, 445, 514, 515, 993, 995, 1080, 1194, 1433, 1702, 1723, 3128, 3268, 3306, 3389, 5432, 5060, 5900, 5938, 8080, 10000, 10050, 20000]
small = [25,80,53,443,445,3389, 8080,8443]

def get_arguments():
    parser = argparse.ArgumentParser(description="ip address to scan for")
    parser.add_argument('-i',dest='iface',type=str,help="enter the interface aka dev", required=True)
    parser.add_argument('-d',dest='ip_addr',type=str,help="enter ip of the target ",required=True)
    parser.add_argument('-l',dest="ports",help="big or small list of ports - b or s ",default='s')
    args=parser.parse_args()
    return args

def scan_m(ip,iface,ports):
    print('[+] start scaning.please wait...\n')
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), iface=iface,timeout=1,verbose=False)
    if ans:
        print("  IP\t\tMAC Address\t\tOpen ports\t\tClosed ports\n----------------------------------------------------------------------------------->")
        if ports == 'b':
            ports=big
        else:
            ports=small
        
        for (s,r,) in ans:
            a,u = sr(IP(dst=r[ARP].psrc)/TCP(sport=33333,dport=ports,flags="S"),iface=iface,timeout=5,verbose=False)
            if a:
                open_ports=[]
                closed_ports=[]
                for (s1,r1) in a:
                    if s1[TCP].dport == r1[TCP].sport and r1[TCP].flags == 'SA':
                        open_ports.append(s1[TCP].dport)

                    elif s1[TCP].dport == r1[TCP].sport and str(r1[TCP].flags) in 'RA':
                        closed_ports.append(s1[TCP].dport)
                if closed_ports:
                    print(Fore.GREEN+r[ARP].psrc+'\t'+r[Ether].src+'\t'+Fore.BLUE+str(open_ports)+ Fore.RESET+'\t'+Fore.RED+str(closed_ports)+ Fore.RESET)
                else:
                    print(Fore.GREEN+r[ARP].psrc+'\t'+r[Ether].src+'\t'+Fore.BLUE+str(open_ports)+ Fore.RESET)
            else:
                print(Fore.RED+r[ARP].psrc+'\t'+r[Ether].src+'\t[fw protected]'+ Fore.RESET)
    else:
         print('[-] host is unreachable.')

def syn_scan(ip,iface):
    print ('[+] making syn scan...')
    
if __name__=='__main__':
    args = get_arguments()
    if re.search('((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.?\\b){4}',args.ip_addr):
        try:
            scan_m(args.ip_addr,args.iface,args.ports)
            print('[+] stop scaning.\n')
        except PermissionError:
            print('\n\r[-] sorry...u need sudo privilege...')
    else:
        print('[-] ip not valid')
