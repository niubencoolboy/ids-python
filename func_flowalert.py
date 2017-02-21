# define the flow alert function
def flowalert(cur_stat,prev_stat):
    alert_list = []

    prev_stat_keys = [] # the exist protocol name
    for dic in prev_stat:
        prev_stat_keys.append(dic['packet_name'])     
    
    for dic2 in cur_stat:
        if dic2.keys()[0] not in prev_stat_keys: # if there is new protocol add into the alert_list
            alert_list.append(dic2)
               
    for i in cur_stat:
        for j in prev_stat:
            if i.keys()[0] == j['packet_name']:
                if (float(i.values()[0]) >= float(str(j['percentage'])) - 0.02 and float(i.values()[0]) <= float(str(j['percentage'])) + 0.02):
                    pass
                else:
                    alert_list.append(i)
    return alert_list
                 
        
# define the function to clear all tables;
def cleartables(cur):
    cur.execute("truncate acid_event")
    cur.execute("truncate data")
    cur.execute("truncate event")
    cur.execute("truncate icmphdr")
    cur.execute("truncate iphdr")
    cur.execute("truncate reference")
    cur.execute("truncate sensor")
    cur.execute("truncate sig_class")
    cur.execute("truncate sig_reference")
    cur.execute("truncate signature")
    cur.execute("truncate tcphdr")
    cur.execute("truncate udphdr")
