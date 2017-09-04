#!/usr/bin/python2

'''
IP package net editor online(Capture, Filter, Modify ...)
Chason DU <chason.du@nokia-sbell.com>

Usage:
===========
[client]# ./neteditor.py

Requirement:
============
pip install NetfilterQueue
pip install scapy

Demo:
============
[server]# nc -u -l 50001
[server]# tcpdump udp port 50001
[client]# nc -u 10.9.245.200 50001
hello world
bad # this package will be drop, and server can not receive this package
start drop # begin drop package
any data will be drop
stop drop # restore the filter
'''

import os, sys, socket
from netfilterqueue import NetfilterQueue
from scapy.all import *
import hexdump

my_drop_flag = 0

def ch_payload_and_send(ip, udp):
    tip  = "Change payload and then send it again\n"
    tip += "Warning: for multi NIC, the changed package maybe can be sent out.\n"
    tip += "As a workaround, you can disable other eths with command 'ifconfig eth2 down'"
    print(tip)

    #print(conf.route)
    newdata = "this is changed payload data!\n"
    pkt = IP(src=ip.src, dst=ip.dst)/UDP(sport=udp.sport, dport=udp.dport)/newdata
    #print(ls(pkt))
    send(pkt)

def callback_process(pkt):
    global my_drop_flag
    print(pkt)

    payload = pkt.get_payload() # str for python 2
    print(type(payload))
    print(pkt.get_hw()) # maybe no Ether data

    print(hexdump.hexdump(payload, "return"))

    #ether = Ether(payload)
    #print(ls(Ether))
    #print("MAC src: " + ether.src)
    #print("MAC dst: " + ether.dst)
    #print("MAC type: " + hex(ether.type))

    ip = IP(payload)
    # print(ls(IP)): list the object IP structure
    print("IP src: " + ip.src)
    print("IP dst: " + ip.dst)
    print("IP length: " + str(ip.len))
    print("IP checksum: " + str(ip.chksum))
    print("IP flags: " + hex(ip.flags))
    print("IP proto: " + str(ip.proto)) # 17: UDP

    udp = ip[UDP]
    # print(ls(UDP))
    print("UDP sport: " + str(udp.sport))
    print("UDP dport: " + str(udp.dport))
    print("UDP length: " + str(udp.len))
    print("UDP payload: " + str(udp.payload))

    ch_payload_and_send(ip, udp)

    data = str(udp.payload)

    if (data == "start drop\n"):
        my_drop_flag = 1
    elif (data == "stop drop\n"):
        my_drop_flag = 0

    # filter
    if (my_drop_flag or data == "bad\n"):
        print("Drop this package!")
        pkt.drop()
    else:
        pkt.accept()


def main():
    q = NetfilterQueue()
    q.bind(0, callback_process)
    try:
        q.run() # block here
    except KeyboardInterrupt:
        print('')
    finally:
        print("Goodbye ...")
        os.system('iptables -D OUTPUT -p udp --dport 50001 -j NFQUEUE --queue-num 0')
        q.unbind()

if __name__ == "__main__":
    print("Welcome to IP Package Editor@Linux!")
    os.system('iptables -I OUTPUT -p udp --dport 50001 -j NFQUEUE --queue-num 0')
    main()


