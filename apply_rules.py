import os 
import linecache
from generate_rulenum import rulenum
from rulestatelist import dictstr2num,rulestr2num,ruleset

path = '/etc/snort/'
config_filename = 'snort.conf'
config_file = path + config_filename
filedata = linecache.getlines(config_file)

init_rule = rulenum

#dict0 =   {10:'onvif_packet',11:'onvif_passwd_det',12:'onvif_buffer_overflow',20:'rtsp_packet',21:'rtsp_passwd_det',22:'rtsp_buffer_overflow',30:'gbt28181_packet',31:'gbt28181_passwd_det',32:'gbt28181_buffer_overflow',40:'rtporrtsp_packet',42:'rtporrtsp_buffer_overflow',50:'icmp_packet',53:'icmp_detection',60:'dns_packet',63:'dns_detection',70:'http_packet',80:'telnet_packet',81:'telnet_passwd_det',82:'telnet_buffer_overflow',83:'telnet_detection',90:'ssh_packet',91:'ssh_passwd_det',92:'ssh_buffer_overflow'}


def generate_replacestr(rulename):
    begin_str = 'include $RULE_PATH/'
    fullname = begin_str + rulename + '.rules'
    fullname_str = fullname + '\n'
    fullname_replacestr = '#' + fullname_str
    return [fullname_str,fullname_replacestr]

def add_rules(rulename):
    rules_lists = generate_replacestr(rulename)
    for i in range(len(filedata)):
	if filedata[i] == rules_lists[1]:
	    filedata[i] = rules_lists[0]


def del_rules(rulename):
    rules_lists = generate_replacestr(rulename)
    for i in range(len(filedata)):
	if filedata[i] == rules_lists[0]:
	    filedata[i] = rules_lists[1]

def bakfile(config_file):
    bakfilename = config_file + '.bak'
    if os.path.exists(bakfilename) == True:
	os.system("sudo rm %s" % bakfilename)
    os.system("sudo cp %s %s" %(config_file,bakfilename))

def change_rulesfile(config_file):
    bakfile(config_file)
    f = open(config_file,'w+')
    for i in filedata:
    	f.write(i)
    f.close()

def applyallrule(test_rule):
    for i in range(len(test_rule)):
    	if test_rule[i] != init_rule[i]:
    	    rule_stat = str(test_rule[i])
    	    rulename = dictstr2num[0][int(rule_stat[0])]
            protocol_options = dictstr2num[1][int(rule_stat[1])]
    	    if protocol_options == 'the protocol data packet':
	        rulename = rulename + '_packet'

    	    if protocol_options == 'password detection':
	    	rulename = rulename + '_passwd_dec'

    	    if protocol_options == 'buffer overflow':
	    	rulename = rulename + '_buffer_overflow'

    	    if protocol_options == 'others detections':
	    	rulename = rulename + '_detection'

            if dictstr2num[2][int(rule_stat[2])] == 'off':
    	    	del_rules(rulename)
            else:
   	    	add_rules(rulename)

def main():

    result, apply_rulestate = rulestr2num(ruleset)
    applyallrule(apply_rulestate)
    bakfile(config_file)
    change_rulesfile(config_file)

if __name__ == "__main__":
    main()

	
	

	
	
