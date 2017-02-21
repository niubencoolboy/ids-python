import linecache

config_file = "/etc/snort/snort.conf"
filedata = linecache.getlines(config_file)

onrule_list = []
offrule_list = []

for i in range(len(filedata)):
    if filedata[i][0:20] == '#include $RULE_PATH/':
	offrule_list.append(filedata[i][20:])
    if filedata[i][0:19] == 'include $RULE_PATH/':
	onrule_list.append(filedata[i][19:])

dict1 = {1:'onvif',2:'rtsp',3:'gbt28181',4:'rtporrtcp',5:'icmp',6:'dns',7:'http',8:'telnet',9:'ssh'}
dict2 = {'packet':0,'passwd':1,'buffer':2,'detection':3}
dict3 = {value:key for key, value in dict1.items()}
dict4 = {0:'the protocol data packet',1:'password detection',2:'buffer overflow',3:'others detections'}
dict5 = {0:'off',1:'on'}

rulenum = []
for i in onrule_list:
    onlist = i.split('_')
    temp1 = onlist[-1].split('.')
    onlist.pop(-1)
    onlist += temp1
    onrulestr = str(dict3[onlist[0]]) + str(dict2[onlist[1]]) + '1'
    rulenum.append(int(onrulestr))

for i in offrule_list:
    offlist = i.split('_')
    temp2 = offlist[-1].split('.')
    offlist.pop(-1)
    offlist += temp2
    offrulestr = str(dict3[offlist[0]]) + str(dict2[offlist[1]]) + '0'
    rulenum.append(int(offrulestr))
    
rulenum.sort()

rulestatelist = []
for i in rulenum:
    rulestate = str(i)
    rulename = dict1[int(rulestate[0])]
    ruleoptions = dict4[int(rulestate[1])]
    ruleonoff = dict5[int(rulestate[2])]
    ruleallsta = rulename + "    " + ruleoptions + "    " + ruleonoff
    rulestatelist.append(ruleallsta)

def main():

    for i in rulestatelist:
	print i

if __name__ == "__main__":
    main()
