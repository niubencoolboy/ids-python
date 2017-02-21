#coding:utf-8
import dboperate
import time
import sys
import datetime
import struct
import socket
import copy

def flow_count():
    conn_db = dboperate.snortdb_connect()
    cur_db = conn_db.cursor()
    #result = cur_db.execute("select count(cid) from event;")
    #current_cid = cur_db.fetchall()
    #print current_cid[0].values()[0]
    #result = cur_db.execute("""select DISTINCT ip_src,ip_dst,sig_name from acid_event where sig_name like %s and cid > %s;""",("%packets",init_cid))
    result = cur_db.execute("""SELECT DISTINCT ip_src, ip_dst, sig_name FROM event INNER JOIN iphdr ON (event.sid=iphdr.sid AND event.cid=iphdr.cid) LEFT JOIN signature on(event.signature=signature.sig_id) where sig_name like "%packets";""")

    iplinks = cur_db.fetchall()
    
    print len(iplinks)
    print iplinks
    print "\n"*2
    flow_oneway_values = []
    begin_time = datetime.datetime.now()
    print "the time of query database is: ",begin_time
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
        packet_len = int(ip_packet_len[0].values()[0]) + count * 14 #加上以太网的14字节
        packets_persec = round(float(count)/internal_time,3) #保留3位小数有效位round()
        flow_persec = round(float(packet_len)/internal_time,3)
        flow_persec = flowunit_convert(flow_persec)
        flow_oneway_values.append((ip_src,ip_dst,proto,packets_persec,flow_persec))
    
    
    flow_insert_values = flow_one2double_way(flow_oneway_values)    
    end_time = datetime.datetime.now()
    print "the time of query over is: ",end_time
    print end_time - begin_time
        
    result = cur_db.execute("select * from IDS_flow_baseline") 
    if result != 0:
        dboperate.clearflowtables(conn_db,'IDS_flow_baseline')
    
    flow_insert_values_tuple = tuple(flow_insert_values)
    print len(flow_insert_values_tuple)
    print flow_insert_values_tuple
    print "\n"*2
    result = cur_db.executemany("insert into IDS_flow_baseline(ip_src,ip_dst,proto,packets_persec,flow_persec) values(%s,%s,%s,%s,%s)",flow_insert_values_tuple)
    conn_db.commit()
    cur_db.close()
    conn_db.close() 
    
def flowunit_convert(init_flow):
    if init_flow < 1024 :
        convert_flow = str(init_flow) + " Bytes/s"
    elif 1024 <= init_flow <= 1048576 :
        convert_flow = str(round(init_flow/1024,3)) + " KB/s"
    else :
        convert_flow = str(round(init_flow/1024/1024,3)) + " MB/s"
    return convert_flow
        
def flow_one2double_way(init_list):
    list_back = copy.deepcopy(init_list)
    flow_doubleway_values = []            
    while len(list_back) >=2:
        for i in range(1,len(list_back)):
            if list_back[0][0] == list_back[i][1] and list_back[0][1] == list_back[i][0] and list_back[0][2] == list_back[i][2] :
                pdb.set_trace()
                insert_tuple = add_double_way(list_back[0],list_back[i])
                list_back.remove(list_back[0])
                list_back.remove(list_back[i])
                flow_doubleway_values.append(insert_tuple)               
                break
            else:
                if i == len(list_back) -1 :
                    pdb.set_trace()
                    insert_tuple = add_double_way(list_back[0])
                    list_back.remove(list_back[0])
                    flow_doubleway_values.append(insert_tuple)
                    break
    else:
        flow_doubleway_values = list_exception(list_back,flow_doubleway_values)
        return flow_doubleway_values
        
        
                

def list_exception(init_list,result_list):
    if len(init_list) == 1:
        insert_tuple = add_double_way(init_list[0])
        flow_doubleway_values = result_list.append(insert_tuple)
    else:
        flow_doubleway_values = result_list
        
    return flow_doubleway_values
        
        
def add_double_way(init_tuple1,init_tuple2=()):           
    if init_tuple2 == ():
        insert_item4 = str(init_tuple1[3]) + " // " + str(0) + " up//down "
        insert_item5 = str(init_tuple1[4]) + " // " + "0 bytes/s" + " up//down "
        insert_tuple = (init_tuple1[0],init_tuple1[1],init_tuple1[2],insert_item4,insert_item5)
        return insert_tuple
    else:
        insert_item4 = str(init_tuple1[3]) + " // " + str(init_tuple2[3]) + " up//down "
        insert_item5 = str(init_tuple1[4]) + " // " + str(init_tuple2[4]) + " up//down "
        insert_tuple = (init_tuple1[0],init_tuple1[1],init_tuple1[2],insert_item4,insert_item5)
        return insert_tuple

def main():
    #global conn_db
    conn_db = dboperate.snortdb_connect()
    dboperate.cleartables(conn_db)
    conn_db.close()
    #cur_db = conn_db.cursor()
    #result = cur_db.execute("select max(cid) from acid_event;")
    #current_cid = cur_db.fetchall()
    #init_cid = current_cid[0].values()[0]
    #print type(init_cid),init_cid
    #conn_db.commit()
    global internal_time
    internal_time = int(sys.argv[1])
    #internal_time = 120
    time.sleep(internal_time)
    flow_count()
    print "the program of ending time is:", datetime.datetime.now()

if __name__ == "__main__":
    main()
    
        
        
    
    
