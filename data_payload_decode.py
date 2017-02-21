#coding:utf-8
import binascii
import dboperate

conn_db = dboperate.snortdb_connect()
cur_db = conn_db.cursor()
#ftp 
result = cur_db.execute("select data_payload from data where cid = '103';")
data_payload = cur_db.fetchall()
data_list = binascii.a2b_hex(data_payload[0]['data_payload'])
data_passwd = data_list[1][0:-2]

#telnet 

result = cur_db.execute("""select iphdr.cid,iphdr.ip_id from iphdr LEFT JOIN event on(iphdr.cid = event.cid) LEFT JOIN signature on(event.signature = signature.sig_id) where sig_name like "%telnet packets" order by cid;""")
telnet_list = cur_db.fetchall()
shell_list = []
for i in range(len(telnet_list)):
    result = cur_db.execute("select data_payload from data where cid =%s",telnet_list[i]['cid'])
    if result != 0:
        data_payload = cur_db.fetchall()
        #if data_payload[0]['data_payload'] in [u'FFFD01', u'0D0A']:
        shell_list.append({telnet_list[i]['ip_id']:data_payload[0]['data_payload']})

tag_cid = []        
for i in range(len(shell_list)):
    if shell_list[i].values()[0] in [u'FFFD01',u'0D0A']:
        tag_cid.append()shell_list[i].keys()[0])
        
shell_str = ''
shell_str_list = []

for i in range(len(tag_cid)-1):
    for j in range(len(shell_list)):
        if shell_list[j].keys()[0] > tag_cid[i] and shell_list[j].keys()[0] < tag_cid[i+1]:
            shell_str += shell_list[j].values()[0]
    shell_str_list.append(binascii.a2b_hex(shell_str))
    shell_str = ''

        
        
            




