#coding:utf-8

import MySQLdb
import MySQLdb.cursors

# 清空snort警告数据表
def cleartables(conn):
    cur = conn.cursor()
    #cur.execute("delete from acid_event")
    cur.execute("delete from data")
    cur.execute("delete from event")
    cur.execute("delete from icmphdr")
    cur.execute("delete from iphdr")
    #cur.execute("delete from reference")
    #cur.execute("delete from sensor")
    #cur.execute("delete from sig_class")
    #cur.execute("delete from sig_reference")
    #cur.execute("delete from signature")
    cur.execute("delete from tcphdr")
    cur.execute("delete from udphdr")
    conn.commit()
    cur.close()
    
#清空流量表    
def clearflowtables(conn,table_name):
    cur = conn.cursor()
    cur.execute("truncate %s" %table_name)
    conn.commit()

#连接snortarc数据库   
def snortarc_connect():
    conn = MySQLdb.connect(host='localhost',db='snortarc',user='snortuser',passwd='snortpasswd',compress=1,cursorclass=MySQLdb.cursors.DictCursor,charset='utf8')
    return conn
#连接snortdb 数据库     
def snortdb_connect():
    conn = MySQLdb.connect(host='localhost',db='snortdb',user='snortuser',passwd='snortpasswd',compress=1,cursorclass=MySQLdb.cursors.DictCursor,charset='utf8')
    return conn

def create_flowlog(conn):
    cur = conn.cursor()
    # create flowlog table
    cur.execute('create table flowlog(id int(10) primary key not null auto_increment,packet_name varchar(100),percentage varchar(20),packet_sum varchar(20));')
    conn.commit()

#插入流量数据
def insert_log(conn,values):
    cur = conn.cursor()
    values = tuple(values)
    if len(values) < 2:    
        cur.execute("insert into flowlog(packet_name,percentage,packet_sum) values(%s,%s,%s)",values)

    else:
        cur.executemany("insert into flowlog(packet_name,percentage,packet_sum) values(%s,%s,%s)",values)
        
    conn.commit()

#插入报警数据
def insert_alert(conn,values):
    cur = conn.cursor()
    values = tuple(values)
    if len(values) < 2:    
        cur.execute("insert into flowalert(protocol,percentage) values(%s,%s)",values)

    else:
        cur.executemany("insert into flowalert(protocol,percentage) values(%s,%s)",values)
        
    conn.commit()


def query_flowlog(conn):

    cur = conn.cursor()

    #添加result变量，不然每次运行脚步，都会有返回结果
    result = cur.execute('select count(cid) from acid_event;')
    flownum = cur.fetchall() # 所有的流量包数量

    #统计报警的种类，这里只有每个协议的包 
    result = cur.execute('select DISTINCT sig_name from acid_event;')
    sig_names = cur.fetchall()

    #统计每个协议包的数量，存储成链表
    sig_cid_list = []
    for sig_name in sig_names:
        case = sig_name.values()[0].encode('utf8')
        result = cur.execute('select count(cid) from acid_event where sig_name = %s',case)
        cid = cur.fetchall()
        cid_mount = int(cid[0].values()[0])
        sig_cid_list.append({case:str(cid_mount)})
    
    #计算每个协议包占的比例
    protocol_percentage = []
    for cid in sig_cid_list:
        percentage = float(cid.values()[0])/float(flownum[0].values()[0])
        protocol_percentage.append({cid.keys()[0]:str(round(percentage,4))})
        
    return sig_cid_list,protocol_percentage


def generate_flowvalues(sig_cid_list,protocol_percentage):
    insert_values = []
    for i in range(len(protocol_percentage)):
        insert_values.append((protocol_percentage[i].keys()[0],protocol_percentage[i].values()[0],sig_cid_list[i].values()[0]))
    return insert_values


def generate_alertvalues(protocol_percentage):
    insert_values = []
    for i in range(len(protocol_percentage)):
        insert_values.append((protocol_percentage[i].keys()[0],protocol_percentage[i].values()[0]))
    return insert_values
     
    
def flowalert(cur_stat,prev_stat):
    alert_list = []
    prev_stat_keys = [] # the exist protocol name
    for dic in prev_stat:
        prev_stat_keys.append(dic['packet_name'])     
    for dic2 in cur_stat:
        if dic2.keys()[0] not in prev_stat_keys: # if there is new protocol add into the alert_list
            alert_list.append(dic2)           
    for i in cur_stat:
        for j in prev_stat:
            if i.keys()[0] == j['packet_name']:
                if (float(str(j['percentage'])) - 0.02) <= float(i.values()[0]) <= (float(str(j['percentage'])) + 0.02):
                    pass
                else:
                    alert_list.append(i)
    return alert_list
    
def update_flow(current_stat,prev_stat,protocol_list):
    update_values = []
    prev_stat_keys = [] # the exist protocol name
    for dic in prev_stat:
        prev_stat_keys.append(dic['packet_name'])  
    
    for i in range(len(current_stat)):
        for j in prev_stat:
            if current_stat[i].keys()[0] == j['packet_name']:
                new_percentage = float(j['percentage']) + float(current_stat[i].values()[0])
                new_percentage = new_percentage/2
                new_packetsum = j['packet_sum'] + long(protocol_list[i].values()[0])
        update_values.append((current_stat[i].keys()[0],new_percentage,new_packetsum))
    return update_values

            
        
    
    



    





