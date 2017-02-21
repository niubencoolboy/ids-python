import commands
import os

def kill_pid(pidname):
    (a,b) = commands.getstatusoutput("sudo ps aux|grep %s |grep -v grep"%pidname)

    os.system("sudo kill %d" %int(b.split()[1]))
