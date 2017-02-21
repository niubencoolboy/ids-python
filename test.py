import os
import linecache


config_file = "/home/john/myrules/test.conf"
filedata = linecache.getlines(config_file)

def generate_replacestr(rulename):
    path = '/home/john/myrules/'
    fullname = path + rulename + '.rules'
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
    if os.path.exists(bakefilename) == True:
	os.system("sudo rm bakefilename")
    os.system("sudo cp %s %s" %(config_file,bakefilename))

def change_rulesfile(config_file):
    bakfile(config_file)
    f = open(config_file,'w+')
    for i in filedata:
    	f.write(i)

    f.close()



 

