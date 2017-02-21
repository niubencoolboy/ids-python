#coding:utf-8

import MySQLdb
import MySQLdb.cursors

# 与本机snort数据库建立连接
conn = MySQLdb.connect(host='localhost',db='snortdb',user='snortuser',passwd='snortpasswd',compress=1,cursorclass=MySQLdb.cursors.DictCursor,charset='utf8')
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
    
#连接远程数据库，这里用笔记本的数据库做实验，用来存储流量统计信息
connarc = MySQLdb.connect(host='10.10.12.7',db='snortarc',user='snortuser',passwd='snortpasswd',compress=1,cursorclass=MySQLdb.cursors.DictCursor,charset='utf8')
curarc = connarc.cursor()

# create flowlog table
curarc.execute('create table flowlog(id int(10) primary key not null auto_increment,packet_name varchar(100),percentage varchar(20));')

#set the values of inserting tables
values = []
for i in range(len(protocol_percentage)):
    values.append((protocol_percentage[i].keys()[0],protocol_percentage[i].values()[0],sig_cid_list[i].values()[0]))
    
#when insert more than one log, use the function -> executemany()
curarc.executemany('insert into flowlog(packet_name,percentage,packet_sum) values(%s,%s,%s)',values)

#query the tables
curarc.execute('select * from flowlog;')
rows =curarc.fetchall()

    

    


