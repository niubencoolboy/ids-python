import os
import linecache

cur_path = "/home/john/IDS/rules-bak"

def main():   
    filename_lists = os.listdir(cur_path)
    for filename in filename_lists:
    	if filename.find(".bak") == -1:
	    changerules(filename)


def changerules(filename):

    fullname = os.path.join(cur_path,filename)
    filedata = linecache.getlines('%s' % fullname)
    f = open(fullname,'a') 
    for i in range(len(filedata)):
	if filedata[i][0:5] == '#aler':
            f.write(filedata[i][1:])
	if filedata[i][0:5] == '# ale':
            f.write(filedata[i][2:])
    f.close()


if __name__ == "__main__":
    main()
    
	

