#coding:utf-8
import dboperate
import struct
import socket
import json
import collections
import sys
import time
import copy
import binascii


def query_alert(cur_db):
    #tcp
    result = cur_db.execute("""select event.timestamp as timestamp,iphdr.cid, iphdr.ip_src,iphdr.ip_dst,tcphdr.tcp_sport as ip_sport,tcphdr.tcp_dport as ip_dport,iphdr.ip_id, sig_name from iphdr LEFT JOIN tcphdr on(iphdr.cid = tcphdr.cid) LEFT JOIN event on(iphdr.cid = event.cid) LEFT JOIN signature on(event.signature=signature.sig_id) where ip_proto = '6';""")
    tcplinks = cur_db.fetchall()
    #udp 
    result = cur_db.execute("""select event.timestamp as timestamp,iphdr.cid, iphdr.ip_src,iphdr.ip_dst,udphdr.udp_sport as ip_sport,udphdr.udp_dport as ip_dport, iphdr.ip_id, sig_name from iphdr LEFT JOIN udphdr on(iphdr.cid = udphdr.cid) LEFT JOIN event on(iphdr.cid = event.cid) LEFT JOIN signature on(event.signature=signature.sig_id) where ip_proto = '17';""")
    udplinks = cur_db.fetchall()
    #icmp 
    result = cur_db.execute("""select event.timestamp as timestamp,iphdr.cid, iphdr.ip_src,iphdr.ip_dst, iphdr.ip_id, sig_name from iphdr LEFT JOIN event on(iphdr.cid = event.cid) LEFT JOIN signature on(event.signature=signature.sig_id) where ip_proto = '1';""")
    icmplinks = cur_db.fetchall()
    #others
    result = cur_db.execute("""select event.timestamp as timestamp,iphdr.cid, iphdr.ip_src,iphdr.ip_dst, iphdr.ip_id, sig_name from iphdr LEFT JOIN event on(iphdr.cid = event.cid) LEFT JOIN signature on(event.signature=signature.sig_id) where ip_proto NOT IN (1,6,17) and sig_name like "%packets" group by ip_src;""")
    other_links = cur_db.fetchall()
    # the all protocol iplinks
    iplinks = tcplinks + udplinks + icmplinks + other_links 
    return iplinks
    
def proto_classify(iplinks):
    flow_alert_output = []
    dns_count = 0
    unanalysis_dns_flow = []
    ssh_count = 0
    unanalysis_ssh_flow = []
    telnet_count = 0
    for communication_event in iplinks:
        current_protocol_name = communication_event['sig_name'].split(" ")[0]
        # HTTP url analysis
        if current_protocol_name == exist_protocol[0] :
            analyzed_event = http_analysis(communication_event)
            flow_alert_output.append(analyzed_event)
        # DNS count
        if current_protocol_name == exist_protocol[1] :
            dns_count += 1
            unanalysis_dns_flow.append(communication_event)
        # SSH count 
        if current_protocol_name == exist_protocol[2] :
            ssh_count += 1
            unanalysis_ssh_flow.append(communication_event)
        # TELNET
        if current_protocol_name == exist_protocol[3] :
            telnet_count += 1
            #analyzed_event = telnet_analysis(communication_event)
            #flow_alert_output.append(analyzed_event)
        # FTP
        if current_protocol_name == exist_protocol[4] :
            analyzed_event = ftp_analysis(communication_event)
            flow_alert_output.append(analyzed_event)
        # ICMP
        if current_protocol_name == exist_protocol[5] :
            analyzed_event = icmp_analysis(communication_event)
            flow_alert_output.append(analyzed_event)
        # others protocol    
        if current_protocol_name not in exist_protocol:
            analyzed_event = otherprotocol_analysis(communication_event)
            flow_alert_output.append(analyzed_event)
    # DNS         
    if dns_count >= 1 : 
        result = cur_db.execute("""SELECT DISTINCT min(event.timestamp) as timestamp, ip_src, ip_dst, sig_name,GROUP_CONCAT(DISTINCT udp_sport) as ip_sport,GROUP_CONCAT(DISTINCT udp_dport) as ip_dport FROM event INNER JOIN iphdr ON (event.sid=iphdr.sid AND event.cid=iphdr.cid) LEFT JOIN signature on(event.signature=signature.sig_id) LEFT JOIN udphdr on(event.cid = udphdr.cid) where iphdr.ip_proto = "17" and sig_name like "%DNS packets" group by ip_src;""")
        dns_event = cur_db.fetchall()
        if len(dns_event) > 1 :
            for i in range(len(dns_event)):
                ip1 = dns_event[i]['ip_src'] 
                ip_src = socket.inet_ntoa(struct.pack('I',socket.htonl(ip1)))
                ip2 = dns_event[i]['ip_dst']
                ip_dst = socket.inet_ntoa(struct.pack('I',socket.htonl(ip2))) #将十进制转换成ip地址字符串。
                proto = dns_event[i]['sig_name'].split()[0]
                values = (ip1,ip2,dns_event[i]['sig_name'])
                result = cur_db.execute("""select count(iphdr.cid) from iphdr LEFT JOIN event on(iphdr.cid = event.cid) LEFT JOIN signature on(event.signature = signature.sig_id) where ip_src=%s and ip_dst=%s and sig_name = %s""",values) #查询包的个数
                count = cur_db.fetchall()[0].values()[0]
                msg = str(round(float(count)/internal_time,2)) + "p/s"
                #import pdb
                #pdb.set_trace()
                analyzed_event = generate_alertdict(dns_event[i],msg)
                flow_alert_output.append(analyzed_event)
        else:
            msg = str(round(float(dns_count)/internal_time,2)) + "p/s"
            analyzed_event = generate_alertdict(dns_event[0],msg)
            flow_alert_output.append(analyzed_event)
    else:
        flow_alert_output += unanalysis_dns_flow
    
    # SSH
    if ssh_count >= 1 :
        result = cur_db.execute("""SELECT DISTINCT min(event.timestamp) as timestamp, ip_src, ip_dst, sig_name,GROUP_CONCAT(DISTINCT tcp_sport) as ip_sport,GROUP_CONCAT(DISTINCT tcp_dport) as ip_dport FROM event INNER JOIN iphdr ON (event.sid=iphdr.sid AND event.cid=iphdr.cid) LEFT JOIN signature on(event.signature=signature.sig_id) LEFT JOIN tcphdr on(event.cid = tcphdr.cid) where iphdr.ip_proto = "6" and sig_name like "%SSH packets" group by ip_src;""")
        ssh_event = cur_db.fetchall()
        if len(ssh_event) > 1 :
            for j in range(len(ssh_event)):
                ip1 = ssh_event[j]['ip_src'] 
                ip_src = socket.inet_ntoa(struct.pack('I',socket.htonl(ip1)))
                ip2 = ssh_event[j]['ip_dst']
                ip_dst = socket.inet_ntoa(struct.pack('I',socket.htonl(ip2))) #将十进制转换成ip地址字符串。
                proto = ssh_event[j]['sig_name'].split()[0]
                values = (ip1,ip2,dns_event[j]['sig_name'])
                result = cur_db.execute("""select count(iphdr.cid) from iphdr LEFT JOIN event on(iphdr.cid = event.cid) LEFT JOIN signature on(event.signature = signature.sig_id) where ip_src=%s and ip_dst=%s and sig_name = %s""",values) #查询包的个数
                count = cur_db.fetchall()[0].values()[0]
                msg = str(round(float(count)/internal_time,2)) + "p/s"
                analyzed_event = generate_alertdict(ssh_event[j],msg)
                flow_alert_output.append(analyzed_event)
        else:
            msg = str(round(float(ssh_count)/internal_time,2)) + "p/s"
            analyzed_event = generate_alertdict(ssh_event[0],msg)
            flow_alert_output.append(analyzed_event)
    else:
        flow_alert_output += unanalysis_ssh_flow
    # telnet
    if telnet_count >= 1 :
        analyzed_event = telnet_analysis(cur_db)
        flow_alert_output.append(analyzed_event)
    #else:
    #    flow_alert_output.append()
    
    return flow_alert_output
        
def http_analysis(current_event):
    event_num = current_event['cid']
    result = cur_db.execute("""select data_payload from data where cid = %s;""",event_num)
    if result != 0 :
        current_datapayload = cur_db.fetchall()
        http_payload = binascii.a2b_hex(current_datapayload[0]['data_payload'])
        #url_tag = ["HOST:","URI:","Allow-Origin:","Location:"]
        #gotten_host_url = [{"host_addr":[]},{"host_uri":[]},{"Allow-Origin":[]},{"Location":[]}]
        for i in range(len(url_tag)):
            if url_tag[i] in http_payload:
                gotten_host_url[i].values()[0].append(http_payload.split(url_tag[i])[1].split("\r\n")[0])
    
    msg = ""
    for i in gotten_host_url:
        if i.values()[0] != [] and len(i.values()[0][0]) >2 :
            msg = i.values()[0][0]
            break
            
    analyzed_event = generate_alertdict(current_event,msg)
    return analyzed_event
    

def telnet_analysis(cur_db):
    result = cur_db.execute("""SELECT DISTINCT min(event.timestamp) as timestamp, ip_src, ip_dst, sig_name,GROUP_CONCAT(DISTINCT tcp_sport) as ip_sport,GROUP_CONCAT(DISTINCT tcp_dport) as ip_dport FROM event INNER JOIN iphdr ON (event.sid=iphdr.sid AND event.cid=iphdr.cid) LEFT JOIN signature on(event.signature=signature.sig_id) LEFT JOIN tcphdr on(event.cid = tcphdr.cid) where iphdr.ip_proto = "6" and sig_name like "%TELNET packets" group by ip_src;""")
    telnet_event = cur_db.fetchall()   
    if len(telnet_event) > 1 :
        shell_list = []
        for k in range(len(telnet_event)):
            shell_list.append([])
            telnet_query_values = (telnet_event[k]['ip_src'],telnet_event[k]['ip_dst'],telnet_event[k]['sig_name']) 
            result = cur_db.execute("""select iphdr.cid,iphdr.ip_id from iphdr LEFT JOIN event on(iphdr.cid = event.cid) LEFT JOIN signature on(event.signature = signature.sig_id) where ip_src=%s and ip_dst=%s and sig_name = %s order by cid;""",telnet_query_values)
            telnet_list = cur_db.fetchall()
            for m in range(len(telnet_list)):
                result = cur_db.execute("select data_payload from data where cid =%s",telnet_list[m]['cid'])
                if result != 0:
                    data_payload = cur_db.fetchall()
                    shell_list[k].append({telnet_list[m]['ip_id']:data_payload[0]['data_payload']})
        tag_cid = [] 
        for i in range(len(shell_list)):
            tag_cid.append([])  
            if shell_list[i] != [] :     
                for shell_list_child in shell_list[i]:
                    if shell_list_child.values()[0] in [u'FFFD01',u'0D0A']:
                        tag_cid[i].append(shell_list_child.keys()[0])
        shell_str = ''
        shell_str_list = []
        for k in range(len(telnet_event)):
            shell_str_list.append([])
            if len(shell_list[k]) > 1 :
                for q in range(len(tag_cid[k])-1):
                    for s in range(len(shell_list[k])):
                        if shell_list[k][s].keys()[0] > tag_cid[k][q] and shell_list[k][s].keys()[0] < tag_cid[k][q+1]:
                            shell_str += shell_list[k][s].values()[0]
                    shell_str_list[k].append(binascii.a2b_hex(shell_str))
                    shell_str = ''
    for i in range(len(telnet_event)):
        if shell_str_list[i] != [] :
            user = shell_str_list[i][0]
            passwd = shell_str_list[i][1]
            other_shell = shell_str_list[i][2:][0]
            msg = "user: " + user + "passwd: " + passwd + "other shells: " + other_shell
        else:
            msg = ""
        analyzed_event = generate_alertdict(telnet_event[i],msg)
    return analyzed_event  


def ftp_analysis(current_event):
    event_num = current_event['cid']
    result = cur_db.execute("""select data_payload from data where cid = %s;""",event_num)
    if result != 0:
        data_payload = cur_db.fetchall()
        data_list = binascii.a2b_hex(data_payload[0]['data_payload'])
        analyzed_event = generate_alertdict(current_event,data_list)
        return analyzed_event     

def icmp_analysis(current_event):
    # icmp 
    #result = cur_db.execute("""SELECT DISTINCT ip_src, ip_dst, sig_name FROM event INNER JOIN iphdr ON (event.sid=iphdr.sid AND event.cid=iphdr.cid) LEFT JOIN signature on(event.signature=signature.sig_id)  where iphdr.ip_proto = "1" and sig_name like "%ICMP packets" group by ip_src;""")
    #icmp_event = cur_db.fetchall()    
    msg = "ping packet"
    analyzed_event = generate_alertdict(current_event,msg)
    return analyzed_event

def otherprotocol_analysis(current_event):
    msg = current_event['sig_name']
    analyzed_event = generate_alertdict(current_event,msg)
    return analyzed_event


def generate_alertdict(current_event,msg):
    tempdict = {}
    tempdict = collections.OrderedDict() #Python字典默认是无序的 导入collections模块 tempdict 变成有序的字典 这样输出就按照赋值的顺序了。
    sip = current_event['ip_src']
    sip = socket.inet_ntoa(struct.pack('I',socket.htonl(sip)))
    dip = current_event['ip_dst']
    dip = socket.inet_ntoa(struct.pack('I',socket.htonl(dip)))
    if 'ip_sport' in current_event.keys():
        sport = current_event['ip_sport']
        dport = current_event['ip_dport']
    else:
        sport = ""
        dport = ""  
    if 'ip_id' in current_event.keys():
        ip_id = current_event['ip_id']
    else:
        ip_id = ""
    #import pdb
    #pdb.set_trace()
    tempdict['timestamp'] = str(current_event['timestamp'])
    tempdict['sip'] = sip
    tempdict['sport'] = sport
    tempdict['dip'] = dip
    tempdict['dport'] = dport
    tempdict['ip_id'] = ip_id
    tempdict['proto'] = current_event['sig_name'].split()[0]
    tempdict['msg'] = msg
 
    return tempdict
    
def main(argv):
    
    conn_db = dboperate.snortdb_connect()
    global cur_db,internal_time,url_tag,gotten_host_url,exist_protocol 
    cur_db = conn_db.cursor()
    internal_time = int(argv)
    url_tag = ["HOST:","URI:","Allow-Origin:","Location:"]
    gotten_host_url = [{"host_addr":[]},{"host_uri":[]},{"Allow-Origin":[]},{"Location":[]}]
    exist_protocol = [u'HTTP',u'DNS',u'SSH',u'TELNET',u'FTP',u'ICMP']
    while True:
        dboperate.cleartables(conn_db)
        time.sleep(internal_time)
        iplinks= query_alert(cur_db)
        flow_alert_output = proto_classify(iplinks)
        #f = open("/home/john/myrules/scripts/alert_output.json",'w')
        #f.write(json.dumps(flow_alert_output))
        output(flow_alert_output)

def output(flow_alert_output):
    process = "ids_communication_event"
    msg = flow_alert_output
    tag = "@output"
    f = open("/home/john/myrules/scripts/alert_output.json",'a')
    f.write(tag + json.dumps({"process":process,"msg":msg}))
    #print tag + json.dumps({"process":process,"msg":msg})
        
if __name__ == "__main__":
    main(sys.argv)
