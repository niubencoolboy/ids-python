#coding:utf-8
from dboperate import *
import time
import sys

def flow_study():
    
    conndb = snortdb_connect()
    protocol_list, protocol_percentage = query_flowlog(conndb)
    flow_values = generate_flowvalues(protocol_list,protocol_percentage)
    
    connarc = snortarc_connect()
    cur_arc = connarc.cursor()
    result = cur_arc.execute('select * from flowlog')
    
    if result == 0:
        insert_log(connarc,flow_values)
    else:
        prev_stat = cur_arc.fetchall()
        alert_list = flowalert(protocol_percentage,prev_stat)
        
        if alert_list == []:
            update_values = update_flow(protocol_percentage,prev_stat,protocol_list)
            insert_log(connarc,update_values)   
        else:
            alert_values = generate_alertvalues(alert_list)
            insert_alert(connarc,alert_values)
            

def main():
    
    internal_time = int(sys.argv[1])
    while True:
        time.sleep(internal_time)
        flow_study()


if __name__ == "__main__":
    main()
    
        
        
    
    
