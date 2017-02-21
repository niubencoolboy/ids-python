for i in iplinks:
    if i['sig_name'].split(" ")[0] == u'HTTP':
        event_num = i['cid']
        result = cur_db.execute("""select data_payload from data where cid = %s;""",event_num)
        if result != 0 :
            current_datapayload = cur_db.fetchall()
            http_payload = binascii.a2b_hex(current_datapayload[0]['data_payload'])
            if "HOST:" in http_payload:
                print i
                host_addr.append(http_payload.split("HOST:")[1].split("\r\n")[0])
            if "URI:" in http_payload:            
                print i              
                host_uri.append(http_payload.split("URI:")[1].split("\r\n")[0])       
            if "Allow-Origin:" in http_payload:
                print i
                host_request_url.append(http_payload.split("Allow-Origin:")[1].split("\r\n")[0])
            if "Location:" in http_payload:
                print i
                host_request_location.append(http_payload.split("Location:")[1].split("\r\n")[0])
                
                
                
                
                
                
                
                
                
                
                
                
                
                
                
                
                
url_tag = ["HOST:","URI:","Allow-Origin:","Location:"]
gotten_host_url = [{"host_addr":[]},{"host_uri":[]},{"Allow-Origin":[]},{"Location":[]}]               
for i in iplinks:
    if i['sig_name'].split(" ")[0] == u'HTTP':
        event_num = i['cid']
        result = cur_db.execute("""select data_payload from data where cid = %s;""",event_num)
        if result != 0 :
            current_datapayload = cur_db.fetchall()
            http_payload = binascii.a2b_hex(current_datapayload[0]['data_payload'])
            for i in range(len(url_tag)):
                if url_tag[i] in http_payload:
                    gotten_host_url[i].values()[0].append(http_payload.split(url_tag[i])[1].split("\r\n")[0])
                    
                    
                    
                    
for i in iplinks:
    if i['sig_name'].split(" ")[0] == u'FTP':
        event_num = i['cid']
        result = cur_db.execute("""select data_payload from data where cid = %s;""",event_num)
        if result != 0 :
            data_payload = cur_db.fetchall()
            data_list = binascii.a2b_hex(data_payload[0]['data_payload'])
            print data_list,type(data_list)
            data_passwd = data_list[1][0:-2]
            print data_passwd
