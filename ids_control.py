#ids control
#coding:utf-8
import os
import argparse
import ids_communication_events

def SetArgs():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--time", type=int, default = 2, help="set the poll database time of a given number")
    parser.add_argument("-s", "--start_ids",choices = ["on","off"], default = "on", help="set the ids turn on or off")
    parser.add_argument("-c", "--communication_event",choices = ["on","off"], default = "on", help="set the communication_event turn on or off")
    parser.add_argument("-a", "--alert_event",choices = ["on","off"], default = "off", help="set the alert_event turn on or off")
    #parser.add_argument("-v", "--verbosity", action="count", default=0,help="increase output verbosity")
    args = parser.parse_args()
    return args

def main():
    args = SetArgs()
    try:
        #开启或者关闭snort
        if args.start_ids == "on":
            os.system("/etc/supervisor/ids_start.sh")
        else:
            os.system("/etc/supervisor/ids_stop.sh")
        #开启通讯事件模块    
        if args.communication_event == "on" :
            ids_communication_events.main(args.time)
        else:
            print "the module of communication_event for ids has closed"

    except KeyboardInterrupt :
        print "the ids control script has been closed!"
    except Exception, e :
        print repr(e)
        
if __name__ == "__main__" :
    main()

    


