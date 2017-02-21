import dboperate
import binascii

conn_db = dboperate.snortdb_connect()
cur_db = conn_db.cursor()

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

# get the cid 
result = cur_db.execute("select data_payload from data where cid = '108'")
data_payload = cur_db.fetchall()
passwd_str = binascii.a2b_hex(data_payload[0]['data_payload'])
passwd = passwd_str.split()[1]
