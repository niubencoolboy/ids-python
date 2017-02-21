import time
import sys


def running(internal_time):
    try:

        while True:
            print 'I am running! %s' %time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
            time.sleep(internal_time)
            print 'I am running again after %d seonds, and the time is %s ' %(internal_time,time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())))
 
    except (KeyboardInterrupt, SystemExit):
        print "CTRL+C received. Killing all workers"

if __name__ == "__main__":
    internal_time = 5
    running(internal_time)

