ruleset = [['onvif',     'the protocol data packet',     'on'], # yes
['onvif',     'password detection',            'on'],                              
['onvif',     'buffer overflow',               'on'],
['rtsp',      'the protocol data packet',      'on'], # yes
['rtsp',      'password detection',            'on'], 
['rtsp',      'buffer overflow',               'on'], # yes
['gbt28181',  'the protocol data packet',      'on'],
['gbt28181',  'password detection',            'on'],
['gbt28181',  'buffer overflow',               'on'],
['rtporrtcp', 'the protocol data packet',      'off'], # not ok
['rtporrtcp', 'buffer overflow',               'on'],
['icmp',      'the protocol data packet',      'on'], # yes
['icmp',      'others detections',             'on'], # yes
['dns',       'the protocol data packet',      'off'], # yes
['dns',       'others detections',             'on'], # yes
['http',      'the protocol data packet',      'on'], # yes
['telnet',    'the protocol data packet',      'on'], # yes
['telnet',    'password detection',            'on'], # yes
['telnet',    'buffer overflow',               'on'], # yes
['telnet',    'others detections',             'on'], # yes
['ssh',       'the protocol data packet',      'on'], # yes
['ssh',       'password detection',            'on'], 
['ssh',       'others detections',             'on']] # yes

dict1 = {1:'onvif',2:'rtsp',3:'gbt28181',4:'rtporrtcp',5:'icmp',6:'dns',7:'http',8:'telnet',9:'ssh'}
dict2 = {0:'the protocol data packet',1:'password detection',2:'buffer overflow',3:'others detections'}
dict3 = {0:'off',1:'on'}
dict4 = {value:key for key, value in dict1.items()}
dict5 = {value:key for key, value in dict2.items()}
dict6 = {value:key for key, value in dict3.items()}
dictstr2num = [dict1,dict2,dict3,dict4,dict5,dict6]

def rulestr2num(ruleset):
    result = []
    rulestatenum =[]
    for i in range(len(ruleset)):
    	if ruleset[i][0] in dict4.keys():
	        if ruleset[i][1] in dict5.keys():
	            rulestatenum.append(str(dict4[ruleset[i][0]]) + str(dict5[ruleset[i][1]]) + str(dict6[ruleset[i][2]]))
	        else:
	    	    result.append("the %s protocol option doesn't exist" % ruleset[i][1])

        else:
	    result.append("the %s protocol doesn't exist" % ruleset[i][0])

    if result == []:
	    result = ["all the protocol apply sucessfully"]
    
    return result,rulestatenum

def main():
    result,rulestatenum =rulestr2num(ruleset)
    print result,rulestatenum

if __name__ == "__main__":
    main()
