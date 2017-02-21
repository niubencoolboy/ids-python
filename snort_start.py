import os

def main():
    os.system("service snort start")
    os.system("barnyard2 -c /etc/snort/barnyard2.conf -d /var/log/snort -f snort.u2 -w /var/log/snort/barnyard2.waldo -g snort -u root -D")
    
if __name__ =="__main__":
    main
        
