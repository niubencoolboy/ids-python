'''
import os 
import string 

def del_files(dir,topdown=True): 
  for root, dirs, files in os.walk(dir, topdown): 
    for name in files: 
      pathname = os.path.splitext(os.path.join(root, name)) 
      if (pathname[1] != ".cpp" and pathname[1] != ".hpp" and pathname[1] != ".h"): 
        os.remove(os.path.join(root, name)) 
        print(os.path.join(root,name)) 

dir = os.getcwd() 
print(dir) 
del_files(dir)
#will delete the self .py file after run !!!-_- 
os.removedirs(dir)

'''



import os

def del_file(path):
    files = os.listdir(path)
    for i in files:
        if i.find("snort.u2") != -1:
	    os.remove(i)

def main():
    #cpath = os.chdir("/var/log/snort")
    del_file(cpath);

if __name__ == "__main__":
    main()

