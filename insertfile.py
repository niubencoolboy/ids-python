import os  
file = open( "a.txt", "r" )  
file_add = open("a.txt","r")  
content = file.read()  
content_add = file_add.read()  
pos = content.find( "buildTypes")
if pos != -1:  
        content = content[:pos] + content_add + content[pos:]  
        file = open( "a.txt", "w" )  
        file.write( content )   

        file.close()  
        file_add.close()  

        print "success"
