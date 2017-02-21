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
    return iplinks

def generate_singal_link(iplinks):    
    flow_oneway_values = []
    for i in range(len(iplinks)):
        ip1 = iplinks[i]['ip_src'] 
        ip_src = socket.inet_ntoa(struct.pack('I',socket.htonl(ip1)))
        ip2 = iplinks[i]['ip_dst']
        ip_dst = socket.inet_ntoa(struct.pack('I',socket.htonl(ip2))) #将十进制转换成ip地址字符串。
        proto = iplinks[i]['sig_name'].split()[0]
        values = (ip1,ip2,iplinks[i]['sig_name'])
        result = cur_db.execute("""select count(iphdr.cid) from iphdr LEFT JOIN event on(iphdr.cid = event.cid) LEFT JOIN signature on(event.signature = signature.sig_id) where ip_src=%s and ip_dst=%s and sig_name = %s""",values) #查询包的个数
        count = cur_db.fetchall()[0].values()[0]
        result = cur_db.execute("""select sum(iphdr.ip_len) from iphdr LEFT JOIN event on(iphdr.cid = event.cid) LEFT JOIN signature on(event.signature = signature.sig_id) where ip_src=%s and ip_dst=%s and sig_name = %s""",values) #查询流量大小(不算以太网的14个字节)
        ip_packet_len = cur_db.fetchall()
        ip_packet_len = int(ip_packet_len[0].values()[0]) + count * 14 #加上以太网的14字节
        packets_persec = round(float(count)/internal_time,3) #保留3位小数有效位round()
        flow_persec = round(float(ip_packet_len)/internal_time,3)
        
        if 'ip_sport' in iplinks[i].keys():
            flow_oneway_values.append((ip_src,iplinks[i]['ip_sport'],ip_dst,iplinks[i]['ip_dport'],proto,packets_persec,flow_persec))
        else:
            flow_oneway_values.append((ip_src,u'',ip_dst,u'',proto,packets_persec,flow_persec)) 
        
    return flow_oneway_values


def flow_one2double_way(init_list):
    list_back = copy.deepcopy(init_list) #用这个函数 修改list_back 原来的list就不会被修改 只修改list_back
    flow_doubleway_values = []            
    while len(list_back) >=2:
        for i in range(len(list_back)-1):
            for j in range(i,len(list_back)):
                if list_back[i][0] == list_back[j][2] and list_back[i][2] == list_back[j][0] and list_back[i][4] == list_back[j][4]:
 # ip_src = ip_dst & ip_proto equal
                    insert_tuple = add_double_way(list_back[i],list_back[j])
                    list_back.remove(list_back[i])
                    list_back.remove(list_back[j])
                    flow_doubleway_values.append(insert_tuple)               
                    break
                else:
                    if j == len(list_back) -1 :
                        insert_tuple = add_double_way(list_back[i])
                        list_back.remove(list_back[i])
                        flow_doubleway_values.append(insert_tuple)
                        break
    else:
        if len(list_back) == 1:
            insert_tuple = add_double_way(list_back[0])
            list_back.remove(list_back[0])
            flow_doubleway_values.append(insert_tuple)
             
    return flow_doubleway_values  

def add_double_way(init_tuple1,init_tuple2=()):           
    if init_tuple2 == ():
        insert_item4 = str(init_tuple1[5]) + " // " + str(0) + " up//down "
        insert_item5 = str(init_tuple1[6]) + " // " + "0 bytes/s" + " up//down "
        insert_tuple = (init_tuple1[0],init_tuple1[1],init_tuple1[2],init_tuple1[3],init_tuple1[4],insert_item4,insert_item5)
        return insert_tuple
    else:
        insert_item4 = str(init_tuple1[5]) + " // " + str(init_tuple2[5]) + " up//down "
        insert_item5 = str(init_tuple1[6]) + " // " + str(init_tuple2[6]) + " up//down "
        insert_tuple = (init_tuple1[0],init_tuple1[1],init_tuple1[2],init_tuple1[3],init_tuple1[4],insert_item4,insert_item5)
        return insert_tuple
    
def generate_alertdict(current_list):
    flow_alert_output = []
    
    for i in current_list:
        tempdict = {}
        tempdict = collections.OrderedDict() #Python字典默认是无序的 导入collections模块 tempdict 变成有序的字典 这样输出就按照赋值的顺序了。
        tempdict['sip'] = i[0]
        tempdict['sport'] = i[1]
        tempdict['dip'] = i[2]
        tempdict['dport'] = i[3]
        tempdict['proto'] = i[4]
        tempdict['p/s'] = i[5]
        tempdict['bytes/s'] = i[6]
        flow_alert_output.append(tempdict) 
    
    return flow_alert_output

def main():
    
    conn_db = dboperate.snortdb_connect()
    global cur_db
    cur_db = conn_db.cursor()
    global internal_time 
    internal_time = int(sys.argv[1])
    while True:
        dboperate.cleartables(conn_db)
        time.sleep(internal_time)
        iplinks= query_alert(cur_db)
        flow_oneway_values = generate_singal_link(iplinks)
        flow_doubleway_values = flow_one2double_way(flow_oneway_values)
        flow_alert_output = generate_alertdict(flow_doubleway_values)
        print json.dumps(flow_alert_output)
        
if __name__ == "__main__":
    main()
