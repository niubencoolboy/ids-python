import os
import linecache

def main():
    filepath = "/etc/snort/rules/"
    protocollist =  ['onvif','rtsp','gbt28181','rtporrtcp','icmp','dns','http','telnet','ssh']
    file_endstr = '_packet.rules'
    temp = 0
    
    for protocolname in protocollist:
        fullname = filepath + protocolname + file_endstr 
        filedata = linecache.getlines(fullname)
        
        for i in range(len(filedata)):
            if filedata[i][0:5] == 'alert':
                filedata[i] = 'log' + filedata[i][5:]
                curstat = 'log'
                temp += 1
                continue
                
            if filedata[i][0:3] == 'log':
                filedata[i] = 'alert' + filedata[i][3:]
                curstat = 'alert'
                temp += 1
                continue
    
        f = open(fullname,'w+')
        for i in filedata:
    	    f.write(i)
        f.close()     

    print curstat,temp
    
if __name__ == "__main__":
    main()
