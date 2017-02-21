import os
from proinfo import processinfo,kill_py

class manage():

    def restart_snort(self):
    	os.chdir("/var/log/snort")
    	os.system("sudo rm barnyard2.waldo")
	os.system("sudo rm snort.u2.*")
    	os.system("sudo service snort restart")
    	os.system("sudo barnyard2 -c /etc/snort/barnyard2.conf -d /var/log/snort -f snort.u2 -w /var/log/snort/barnyard2.waldo -g snort -u root -D")
    	#os.system("sudo python /home/john/myrules/scripts/flowstudy.py 120 &")


    def stop_snort(self):
    	os.system("sudo service snort stop")
        os.system("sudo kill %d" % int(processinfo('barnyard2')[0]))
        #kill_py('flowstudy.py')
        


    def start_snort(self):
    	os.system("sudo service snort start")
        os.system("sudo barnyard2 -c /etc/snort/barnyard2.conf -d /var/log/snort -f snort.u2 -w /var/log/snort/barnyard2.waldo -g snort -u root -D")
        #os.system("sudo python /home/john/myrules/scripts/flowstudy.py 120 &")



