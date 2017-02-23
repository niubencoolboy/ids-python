import pcap
import dpkt

def captData():
    pc=pcap.pcap('eth1')  #注，参数可为网卡名，如eth0
    pc.setfilter('tcp port 80')    #设置监听过滤器
    for ptime,pdata in pc:    #ptime为收到时间，pdata为收到数据
        anlyCap(pdata);
        
def anlyCap(pdata):
    p=dpkt.ethernet.Ethernet(pdata)
    if p.data.__class__.__name__=='IP':
        ip='%d.%d.%d.%d'%tuple(map(ord,list(p.data.dst)))
        if p.data.data.__class__.__name__=='TCP':
            if p.data.data.dport==80:
                print p.data.data.data # http 请求的数据  
