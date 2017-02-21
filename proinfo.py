import psutil
import re
import sys
import commands
import os

def processinfo(x):
    pidnum = []
    p = psutil.get_process_list()
    for r in p:
	    aa = str(r)
	    f = re.compile(x,re.I)
	    if f.search(aa):
 	        pidnum.append(aa.split('pid=')[1].split(',')[0])
	   # print aa.split('pid=')
    return pidnum
'''   
if __name__ =="__main__":
    print processinfo(sys.argv[1])
    
'''

def kill_py(pidname):
    (a,b) = commands.getstatusoutput("sudo ps aux|grep %s |grep -v grep"%pidname)
    if b != '':
        os.system("sudo kill %d" %int(b.split()[1]))
