#coding:utf8
#输出模块
#一 漏洞探测模块
#定制输出项 
#1. 输出 攻击者IP 即ip_src 被攻击对象ip_dst  
    
#    eg:select DISTINCT ip_src,ip_dst from acid_event;

#2. 攻击协议 protocol  攻击类型：缓冲区溢出还是弱口令探测
#3. 攻击时间 开始和结束时间  begining time   ending time
#4. 攻击数量 即使 count(acid_cid) 
#5.             

#二 流量异常模块
#1. 输出 源目的IP 
#2. 协议名称  
#3. 报警up 还是 down 多少个
import dboperate
import struct
import socket
import json
import collections

# ip = socket.inet_ntoa(struct.pack('I',socket.htonl(int_ip)))  整数转换IP地址
# socket.ntohl(struct.unpack("I",socket.inet_aton(str(ip)))[0])  IP地址转换整数
# create table IDS_flow_baseline(id int(10) primary key not null auto_increment,ip1 int(20) unsigned,ip2 int(20) unsigned,proto varchar(50),count int(10)); 创建流量数据库
#select count(cid) from acid_event where ip_src='1920103026' and ip_dst='168430600' and sig_name = 'DNS packets';
#select DISTINCT ip_src,ip_dst, sig_name from acid_event;

class snort_vulalert:
    def __init__(self,*argv):
        self.v = list(argv)
    
    def __str__(self):          
        print str(self.v)
    
    def Additems(self,item):
        self.v.append(item)
        
    
    
conn_db = dboperate.snortdb_connect()

def query_alert(conn_db):
    cur_db = conn_db.cursor()
    result = cur_db.execute("select DISTINCT ip_src,ip_dst,sig_name from acid_event;")
    iplinks = cur_db.fetchall()
    
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

json.dumps(IDS_snort_vul)

    

    
    
    
    
    
    
    
class snort_flowalert:
    def 
    
    
    
    
    
    
    
cur_db = conn_db.cursor()
result = cur_db.execute("select * from IDS_flow_baseline") 
if result != 0:
    flow_baseline = cur_db.fetchall()
    dboperate.clearflowtables(conn_db,'IDS_flow_baseline')

current_flow = []
flow_insert_values = []
for i in range(len(iplinks)):
    ip1 = iplinks[i]['ip_src']
    ip2 = iplinks[i]['ip_dst']
    proto = iplinks[i]['sig_name'].split()[0]
    values = (ip1,ip2,iplinks[i]['sig_name'])
    result = cur_db.execute("select count(cid) from acid_event where ip_src=%s and ip_dst=%s and sig_name = %s",values)
    count = cur_db.fetchall()[0]['count(cid)']
    current_flow.append({"ip1":ip1,"ip2":ip2,"proto":proto,"count":count})
    flow_insert_values.append((ip1,ip2,proto,count)) 
    

    
flow_insert_values_tuple = tuple(flow_insert_values)
result = cur_db.executemany("insert into IDS_flow_baseline(ip1,ip2,proto,count) values(%s,%s,%s,%s)",flow_insert_values_tuple)
conn_db.commit()

def generate_alertflow(flow_baseline,current_flow):
    alertflow_list = []
    
    current_flow_back = current_flow
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
        tempdict["count"] = abs(tempdict["count"])
        
    for tempdict in current_flow_back:
        tempdict["msg"] = "up"
        
    for tempdict in flow_baseline_back:
        del tempdict["id"]
        tempdict["msg"] = "down"
        
    alertflow_list = alertflow_list + current_flow_back + flow_baseline_back
        
        








IDS_snort_flow = []
    tempdict = {}
    tempdict = collections.OrderedDict() #Python字典默认是无序的 导入collections模块 tempdict 变成有序的字典 这样输出就按照赋值的顺序了。
    tempdict['ip1'] = socket.inet_ntoa(struct.pack('I',socket.htonl(ip1)))
    tempdict['ip2'] = socket.inet_ntoa(struct.pack('I',socket.htonl(ip2)))
    tempdict['proto'] = str(proto)
    tempdict['count'] = count 
    IDS_snort_flow.append({"@IDS_snort_flow":tempdict})

