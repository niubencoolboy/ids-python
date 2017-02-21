#coding:utf-8
import sys
import time
import socket
import struct
import collections
import json
import os
import datetime
#import time
import dboperate
    
def query_vul_iplinks():
    #print time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
    conn_db = dboperate.snortdb_connect()
    cur_db = conn_db.cursor()
    #print "the time of query database is:", datetime.datetime.now()
    #result = cur_db.execute("select max(cid) from acid_event;")
    #current_cid = cur_db.fetchall()
    #print current_cid[0].values()[0]
    #result = cur_db.execute("""select DISTINCT ip_src,ip_dst,sig_name from acid_event where sig_name like %s or sig_name like %s;""",("buffer overflow","passwd detection"))
    #result = cur_db.execute("select count(cid) from event;")
    #count_cid = cur_db.fetchall()
    #print "count_cid: %s" %count_cid 
    #tcp
    result = cur_db.execute("""SELECT DISTINCT ip_src, ip_dst, sig_name,GROUP_CONCAT(DISTINCT tcp_sport) as ip_sport,GROUP_CONCAT(DISTINCT tcp_dport) as ip_dport FROM event INNER JOIN iphdr ON (event.sid=iphdr.sid AND event.cid=iphdr.cid) LEFT JOIN signature on(event.signature=signature.sig_id) LEFT JOIN tcphdr on(event.cid = tcphdr.cid) where iphdr.ip_proto = "6" and sig_name like "%packets" group by ip_src;""")
    tcplinks = cur_db.fetchall()


    #udp 
    result = cur_db.execute("""SELECT DISTINCT ip_src, ip_dst, sig_name,GROUP_CONCAT(DISTINCT udp_sport) as ip_sport,GROUP_CONCAT(DISTINCT udp_dport) as ip_dport FROM event INNER JOIN iphdr ON (event.sid=iphdr.sid AND event.cid=iphdr.cid) LEFT JOIN signature on(event.signature=signature.sig_id) LEFT JOIN udphdr on(event.cid = udphdr.cid) where iphdr.ip_proto = "17" and sig_name like "%packets" group by ip_src;""")
    udplinks = cur_db.fetchall()


    #icmp 
    result = cur_db.execute("""SELECT DISTINCT ip_src, ip_dst, sig_name FROM event INNER JOIN iphdr ON (event.sid=iphdr.sid AND event.cid=iphdr.cid) LEFT JOIN signature on(event.signature=signature.sig_id)  where iphdr.ip_proto = "1" and sig_name like "%packets" group by ip_src;""")
    icmplinks = cur_db.fetchall()

    #others
    result = cur_db.execute("""SELECT DISTINCT ip_src, ip_dst, sig_name FROM event INNER JOIN iphdr ON (event.sid=iphdr.sid AND event.cid=iphdr.cid) LEFT JOIN signature on(event.signature=signature.sig_id) where ip_proto NOT IN (1,6,17) and sig_name like "%packets" group by ip_src;""")
    other_links = cur_db.fetchall()

    # the all protocol iplinks
    iplinks = tcplinks + udplinks + icmplinks + other_links
    
    cur_db.close()
    conn_db.commit()

"""
def GetSwitchIp():
    conn_db = dboperate.snortdb_connect()
    cur_db = conn_db.cursor()    
    result = cur_db.execute("""select ip_addr from IDS_switch_information;""")
    switch_ip = cur_db.fetchall()
    switch_ip_list = []
    for i in switch_ip:
        switch_ip_list.append(str(i['ip_addr']))
    
    cur_db.close()
    conn_db.close()
    return switch_ip_list


def Filter_ip(iplinks,switch_ip_list):
    iplinks_list = list(iplinks)
    for alert_list in iplinks:
        ip_src = socket.inet_ntoa(struct.pack('I',socket.htonl(alert_list['ip_src'])))#将数据库存储的十进制的IP地址转化成0.0.0.0格式的字符串
        ip_dst = socket.inet_ntoa(struct.pack('I',socket.htonl(alert_list['ip_dst'])))
        if ip_src in switch_ip_list:
            continue
        else:
            if ip_dst in switch_ip_list:
                continue
            else:
                iplinks_list.remove(alert_list)
    
    print "\n"
    print iplinks_list
    print len(iplinks_list)
    return iplinks_list

"""
def generate_vul_alert(iplinks):  
    IDS_snort_vul = []
    for i in range(len(iplinks)):
        sip = iplinks[i]['ip_src']
        sip = socket.inet_ntoa(struct.pack('I',socket.htonl(sip)))
        dip = iplinks[i]['ip_dst']
        dip = socket.inet_ntoa(struct.pack('I',socket.htonl(dip)))
        proto = iplinks[i]['sig_name'].split()[0] #sig_name 第一个字符串表示协议
        msg = iplinks[i]['sig_name'].split()[1:][0] #sig_name 从第二项开始 表示报警信息
        tempdict = {}
        tempdict = collections.OrderedDict() #Python字典默认是无序的 导入collections模块 tempdict 变成有序的字典 这样输出就按照赋值的顺序了。
        tempdict['sip'] = sip
        tempdict['dip'] = dip
        tempdict['proto'] = str(proto)
        tempdict['msg'] = str(msg)
        IDS_snort_vul.append({"@IDS_snort_vul":tempdict})

    return IDS_snort_vul

def main():
    #conn_db = dboperate.snortdb_connect() # connect to the database
    #print "the time of clear database is:", datetime.datetime.now()
    #os.system("supervisorctl stop barnyard2")
    #dboperate.cleartables(conn_db) #delete all the date
    #conn_db.close() 
    #os.system("supervisorctl start barnyard2")
    #print "the time of starting sleeping is:", datetime.datetime.now()
    internal_time = int(sys.argv[1]) #read the given the sleep argument
    #switch_ip_list = GetSwitchIp() #get the all ip in the switch
    #print switch_ip_list

    while True:
        conn_db = dboperate.snortdb_connect() # connect to the database
        #print "the time of clear database is:", datetime.datetime.now()
        dboperate.cleartables(conn_db) #delete all the date
        #cur_db = conn_db.cursor()
        #result = cur_db.execute("select max(cid) from acid_event;")
        #current_cid = cur_db.fetchall()
        #init_cid = current_cid[0].values()[0]
        #print type(init_cid),init_cid
        #cur_db.close()
        conn_db.close()
        #print "the time of starting sleeping is:", datetime.datetime.now() 
        time.sleep(internal_time) #sleep
        iplinks = query_vul_iplinks()#get the vul alert information
        #filter_iplink_list = Filter_ip(iplinks,switch_ip_list) #filter the ip which is not belong to the switch
        IDS_snort_vul = generate_vul_alert(filter_iplink_list) #generate the output list
        #print "\n"
        print json.dumps(IDS_snort_vul)
        print "the program of ending time is:", datetime.datetime.now()
        print "\n"*2
        
if __name__ == "__main__":
    main()
