import time
import sys
def main(argv):
    internal_time = int(sys.argv[1])
    json = [{"sip": "163.177.84.16", "sport": 80, "dip": "10.10.12.8", "dport": 44666, "ip_id": 0, "proto": "HTTP", "msg": ""}]
    while True:
        output(json)
        time.sleep(internal_time)

def output(json):
    process = "ids_communication_event"
    print {"process":process,"msg":json}
        
if __name__ == "__main__":
    main(sys.argv)
