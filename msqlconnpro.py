#coding:utf-8

import MySQLdb
import MySQLdb.cursors

conn = MySQLdb.connect(host='10.10.12.7',db='snortarc',user='snortuser',passwd='snortpasswd',compress=1,cursorclass=MySQLdb.cursors.DictCursor,charset='utf8')
cur = conn.cursor()
cur.execute('select * from acid_event;')
rows = cur.fetchall()

