# -*- coding: utf-8 -*-

import os
import sys
import time
import re
import argparse
from scapy.all import *
import requests
from bs4 import BeautifulSoup
from terminaltables import AsciiTable

def ispublic(ip):
    from IPy import IP
    ip = IP(ip)
    return ip.iptype() == 'PUBLIC'

class IPVoid():

    url = 'http://www.ipvoid.com/scan/{ip}'

    @classmethod
    def make_request(cls, ip):
        rq = requests.get(cls.url.format(ip=ip))
        return rq.text

    @classmethod
    def extract_info(cls, response):

        soup = BeautifulSoup(response, 'html.parser')

        if soup.find('table'):
            domain = soup.table.findAll('td')[7].text
            owner  = soup.table.findAll('td')[11].text
            status = soup.table.findAll('td')[3].text
            return [domain, owner, status]
        else:
            return ['Unknown'] * 3
            
            
def print_report(data):
    os.system('clear')
    report = AsciiTable(data)
    print(report.table)

def main(iface):
    os.system('clear')
    try:
        ips  = set()
        data = [['IP', 'Domain', 'Owner', 'Status']]
        ipvoid = IPVoid()

        while True:
            packets = sniff(iface=iface, count=5)
            time.sleep(1)
            for packet in packets:
                if IP in packet:
                    ip_dst = packet[IP].dst
                    if ip_dst not in ips and ispublic(ip_dst):
                        r = ipvoid.make_request(ip_dst)
                        row = ipvoid.extract_info(r)
                        row.insert(0, ip_dst)
                        data.append(row)
                        ips.add(ip_dst)
            print_report(data)
    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Check your the destiny ip of your packets against ipvoid.org.')
    parser.add_argument('-i', default='eth0', help='Listen on interface. If unspecified, uses eth0')
    args = parser.parse_args()
    main(args.i)

