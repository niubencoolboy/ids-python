#coding:utf-8
##同一个文件夹下面
import os

filename_lists = os.listdir(path)
fullname = []

for filename in filename_lists:
    fullname.append(os.path.join(path,filename))

for fi in fullname:
    if fi.find(".bak") == -1:
        os.system("cp %s %s" % (fi,fi+".bak"))    


##不同文件夹
def bakfile(source_path,des_path):
    
    filename_lists = os.listdir(source_path)
    
    source_fullname =[]
    des_fullname = []
    for filename in filename_lists:
	source_fullname = os.path.join(source_path,filename)
	des_fullname = os.path.join(des_path,filename+".bak")
	os.system("cp %s %s" % (source_fullname,des_fullname))

