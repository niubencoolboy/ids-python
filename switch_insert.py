values=[('c4:54:44:00:ca:50', '10.10.12.7', 1), ('00:42:43:ae:03:39', '10.10.12.9', 2), ('cc:52:af:4a:4a:08', '10.10.12.13', 3), ('cc:52:af:4a:4a:6c', '10.10.12.21', 4), ('28:d2:44:3d:47:6e', '10.10.12.24', 5), ('28:d2:44:25:63:87', '10.10.12.23', 6),('28:D2:44:3D:47:6E','10.10.12.24',7),('6C:0B:84:3C:75:D5','10.10.12.25',8),('28:D2:44:20:54:4A','10.10.12.26',9),('FC:D7:33:B2:56:8D','10.10.12.27',10),('6c:0b:84:42:84:24','10.10.12.8',11)]
values_tuple = tuple(values)
import dboperate
conn_db = dboperate.snortdb_connect()
cur_db = conn_db.cursor()
result = cur_db.executemany("""insert into IDS_switch_information(mac_addr,ip_addr,switch_port) values(%s,%s,%s)""",values_tuple)
conn_db.commit()

