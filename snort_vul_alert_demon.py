#coding:utf-8
import dboperate
import struct
import socket
import json
import collections
import sys
import time
import copy

def query_alert(cur_db):
    #tcp
    result = cur_db.execute("""select iphdr.ip_src,iphdr.ip_dst,tcphdr.tcp_sport,tcphdr.tcp_dport,iphdr.ip_id, sig_name from iphdr LEFT JOIN tcphdr on(iphdr.cid = tcphdr.cid) LEFT JOIN event on(iphdr.cid = event.cid) LEFT JOIN signature on(event.signature=signature.sig_id) where ip_proto = '6';""")
    tcplinks = cur_db.fetchall()
    #udp 
    result = cur_db.execute("""select iphdr.ip_src,iphdr.ip_dst,udphdr.udp_sport,udphdr.udp_dport, iphdr.ip_id, sig_name from iphdr LEFT JOIN udphdr on(iphdr.cid = udphdr.cid) LEFT JOIN event on(iphdr.cid = event.cid) LEFT JOIN signature on(event.signature=signature.sig_id) where ip_proto = '17';""")
    udplinks = cur_db.fetchall()
    #icmp 
    result = cur_db.execute("""select iphdr.ip_src,iphdr.ip_dst, iphdr.ip_id, sig_name from iphdr LEFT JOIN event on(iphdr.cid = event.cid) LEFT JOIN signature on(event.signature=signature.sig_id) where ip_proto = '1';""")
    icmplinks = cur_db.fetchall()
    #others
    result = cur_db.execute("""select iphdr.ip_src,iphdr.ip_dst, iphdr.ip_id, sig_name from iphdr LEFT JOIN event on(iphdr.cid = event.cid) LEFT JOIN signature on(event.signature=signature.sig_id) where ip_proto NOT IN (1,6,17) and sig_name like "%packets" group by ip_src;""")
    other_links = cur_db.fetchall()ds
    # the all protocol iplinks
    iplinks = tcplinks + udplinks + icmplinks + other_links 
    return iplinks
