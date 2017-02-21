#coding:utf8
#输出模块
import dboperate
import struct
import socket
import json
import collections
import sys

   
    

def query_alert(cur_db):
    result = cur_db.execute("select DISTINCT ip_src,ip_dst,sig_name from acid_event;")
    iplinks = cur_db.fetchall()
    return iplinks

def update_flowbaseline(cur_db,flow_insert_values):    
    flow_insert_values_tuple = tuple(flow_insert_values)
    result = cur_db.executemany("insert into IDS_flow_baseline(ip1,ip2,proto,count) values(%s,%s,%s,%s)",flow_insert_values_tuple)
    conn_db.commit()

def generate_flowalert(flow_baseline,current_flow):
    alertflow_list = []
    
    current_flow_back = current_flow
    current_flow = tuple(current_flow) #一定要转化成元祖
    flow_baseline_back = list(flow_baseline)
    
    for i in range(len(current_flow)):
        for j in range(len(flow_baseline)):
            if current_flow[i]['ip2'] in flow_baseline[j].values() and current_flow[i]['ip1'] in flow_baseline[j].values() :
                if current_flow[i]['proto'] == flow_baseline[j]['proto']:
                    if current_flow[i]['count'] != flow_baseline[j]['count']:
                        alertflow_list.append({"ip1":current_flow[i]['ip1'],"ip2":current_flow[i]['ip2'],"proto":current_flow[i]['proto'],"count":current_flow[i]['count']-flow_baseline[j]['count']})
                    current_flow_back.remove(current_flow[i])
                    flow_baseline_back.remove(flow_baseline[j])
                    break
     
    for tempdict in alertflow_list:
        if tempdict["count"] > 0:
            tempdict["msg"] = "up"
        else:
            tempdict["msg"] = "down"    
        tempdict["count"] = abs(tempdict["count"]) # abs() 函数 绝对值函数
        
    for tempdict in current_flow_back:
        tempdict["msg"] = "up"
        
    for tempdict in flow_baseline_back:
        del tempdict["id"]
        tempdict["msg"] = "down"
        
    alertflow_list = alertflow_list + current_flow_back + flow_baseline_back
    
    return alertflow_list
        
def snort_vul_alert():  
    conn_db = dboperate.snortdb_connect()
    cur_db = conn_db.cursor()
    iplinks = query_alert(cur_db)  
    IDS_snort_vul = []
    for i in range(len(iplinks)):
        attacker = iplinks[i]['ip_src']
        attacker = socket.inet_ntoa(struct.pack('I',socket.htonl(attacker)))
        victim = iplinks[i]['ip_dst']
        victim = socket.inet_ntoa(struct.pack('I',socket.htonl(victim)))
        proto = iplinks[i]['sig_name'].split()[0] #sig_name 第一个字符串表示协议
        msg = iplinks[i]['sig_name'].split()[1:][0] #sig_name 从第二项开始 表示报警信息
        tempdict = {}
        tempdict = collections.OrderedDict() #Python字典默认是无序的 导入collections模块 tempdict 变成有序的字典 这样输出就按照赋值的顺序了。
        tempdict['attacker'] = attacker
        tempdict['victim'] = victim
        tempdict['proto'] = str(proto)
        tempdict['msg'] = str(msg)
        IDS_snort_vul.append({"@IDS_snort_vul":tempdict})

    return IDS_snort_vul

    

def snort_flow_alert(): 
    conn_db = dboperate.snortdb_connect()
    cur_db = conn_db.cursor()
    iplinks = query_alert(cur_db)   
    result = cur_db.execute("select * from IDS_flow_baseline") 
    flow_baseline = cur_db.fetchall()
    
    current_flow = []
    #flow_insert_values = []
    for i in range(len(iplinks)):
        ip1 = iplinks[i]['ip_src']
        ip2 = iplinks[i]['ip_dst']
        proto = iplinks[i]['sig_name'].split()[0]
        values = (ip1,ip2,iplinks[i]['sig_name'])
        result = cur_db.execute("select count(cid) from acid_event where ip_src=%s and ip_dst=%s and sig_name = %s",values)
        count = cur_db.fetchall()[0]['count(cid)']
        current_flow.append({"ip1":ip1,"ip2":ip2,"proto":proto,"count":count})
        #flow_insert_values.append((ip1,ip2,proto,count)) 
    
    alertflow_list = generate_flowalert(flow_baseline,current_flow)
    IDS_snort_flow = []
    
    for i in alertflow_list:
        tempdict = {}
        tempdict = collections.OrderedDict() #Python字典默认是无序的 导入collections模块 tempdict 变成有序的字典 这样输出就按照赋值的顺序了。
        ip1 = i['ip1']
        ip2 = i['ip2']
        tempdict['ip1'] = socket.inet_ntoa(struct.pack('I',socket.htonl(ip1)))
        tempdict['ip2'] = socket.inet_ntoa(struct.pack('I',socket.htonl(ip2)))
        tempdict['proto'] = i['proto']
        tempdict['msg'] = i['msg']
        tempdict['count'] = i['count']
        IDS_snort_flow.append({"@IDS_snort_flow":tempdict})
    
    return IDS_snort_flow
    
def output(*argv):
    argv = list(argv)
    if len(argv) == 1:
        if argv[0] == "flowalert":
            IDS_snort_flow = snort_flow_alert()
            return json.dumps(IDS_snort_flow)
        elif argv[0] == "vulalert":
            IDS_snort_vul = snort_vul_alert()
            return json.dumps(IDS_snort_vul)
        else:
            print "the value of argv is wrong!"
    elif len(argv) == 2:
        if argv == ["flowalert","vulalert"] or argv == ["vulalert","flowalert"]:
            IDS_snort_flow = snort_flow_alert()
            IDS_snort_vul = snort_vul_alert()
            return json.dumps(IDS_snort_flow + IDS_snort_vul)
        else:
            print "the value of argv is wrong!"
    else:
        print "the number of argv are/is not right!"









