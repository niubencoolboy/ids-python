###############################################################################################
#
#  mysqlconn.py
#  下面的结果返回的是元祖，元祖的元素是还是元祖，这样数据拿到不知道是什么。
#  mysqlconnpro.py  的返回结果是元祖，但是元素是字典，字典的keys对应数据表的值，非常方便。
#
###############################################################################################

#coding=utf-8

import MySQLdb

#建立与数据库的链接
conn = MySQLdb.connect(db='snortdb',host='10.10.12.7',user='snortuser',passwd='snortpasswd')

#获取操作游标
cur = conn.cursor()

#执行SQL
cur.execute('show databases;')
#查看一条记录
print cur.fetchone()
#查询多条用fetchmany()  此时游标已经后移一位
print cur.fetchmany(2)

#怎么游标重置？ 看下面
cur.scroll(0,mode='absolute')
print cur.fetchmany(3)

#自定义每次数据库操作后的查询工作
def showinfo():
    for data in cur.fetchall():
        print data
    
#创建数据库 但是此时的数据库用户没有权限
#cur.execute('''create database if not exists databasename''')

#选择数据库
conn.select_db('snortdb')

#创建数据表
cur.execute('''create table test(id int, info varchar(100))''')
value = [1,"inserted?"]
#插入一条记录
cur.execute("insert into test values(%s,%s)",value)
cur.execute('show tables;')
showinfo()

cur.execute('select * from test;')
showinfo()
#创建多记录list
values = []
for i in range(20):
    values.append((i,'Hello mysqldb, I am the recoder ' + str(i)))
#插入多条用executemany()
cur.executemany("""insert into test values(%s,%s)""",values)

cur.execute('select * from test;')
showinfo()

#删除id编号=1，这里删除了两个
cur.execute('delete from test where id = 1;')
cur.execute('select * from test;')
showinfo()

cur.execute('insert into test values(%s,%s)',(1,'insert id=1'))
cur.execute('select * from test;')
showinfo()

#按照ID编号大小进行查询
cur.execute('select * from test order by id;')
showinfo()
#删除数据表
cur.execute('drop table test;')
cur.execute('show tables;')
showinfo()


