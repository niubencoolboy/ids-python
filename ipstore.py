iplastnumlists=[7,8,9,13,21,23,24,25,26,27,29,31,40,43,46,47,52,54,56,57,73,84,86,88,90,94,95,99,103,106,123,133,147,151,156,165,171,174,184,190,192,198,200,203,209,242,246]


#alliplists = []
#for i in iplastnumlists:
#    alliplists.append('10.10.12.' + str(i))

#dict1 = {1:'NVR',2:'DVR',3:'CAMERA',4:'IPC',5:'OTHER DEVICES'}

#alldevice_list= []
#for i in range(len(alliplists)):
#    if alliplists[i] == '10.10.12.8':
#        alldevice_list.append({alliplists[i]:'SNORT'})
#    else:
#	alldevice_list.append({alliplists[i]:dict1[i % 5 + 1]})

alldevice_list = [{'10.10.12.7': 'NVR'}, {'10.10.12.8': 'SNORT'}, {'10.10.12.9': 'DVR'}, {'10.10.12.13': 'IPC'}, {'10.10.12.21': 'OTHER DEVICES'}, {'10.10.12.23': 'NVR'}, {'10.10.12.24': 'DVR'}, {'10.10.12.25': 'CAMERA'}, {'10.10.12.26': 'IPC'}, {'10.10.12.27': 'OTHER DEVICES'}, {'10.10.12.29': 'CAMERA'}, {'10.10.12.31': 'IPC'}, {'10.10.12.40': 'CAMERA'}, {'10.10.12.43': 'IPC'}, {'10.10.12.46': 'OTHER DEVICES'}, {'10.10.12.47': 'CAMERA'}, {'10.10.12.52': 'IPC'}, {'10.10.12.54': 'CAMERA'}, {'10.10.12.56': 'IPC'}, {'10.10.12.57': 'OTHER DEVICES'}, {'10.10.12.73': 'CAMERA'}, {'10.10.12.84': 'IPC'}, {'10.10.12.86': 'CAMERA'}, {'10.10.12.88': 'IPC'}, {'10.10.12.90': 'OTHER DEVICES'}, {'10.10.12.94': 'CAMERA'}, {'10.10.12.95': 'IPC'}, {'10.10.12.99': 'CAMERA'}, {'10.10.12.103': 'IPC'}, {'10.10.12.106': 'OTHER DEVICES'}, {'10.10.12.123': 'CAMERA'}, {'10.10.12.133': 'IPC'}, {'10.10.12.147': 'CAMERA'}, {'10.10.12.151': 'IPC'}, {'10.10.12.156': 'OTHER DEVICES'}, {'10.10.12.165': 'CAMERA'}, {'10.10.12.171': 'IPC'}, {'10.10.12.174': 'CAMERA'}, {'10.10.12.184': 'IPC'}, {'10.10.12.190': 'OTHER DEVICES'}, {'10.10.12.192': 'CAMERA'}, {'10.10.12.198': 'IPC'}, {'10.10.12.200': 'CAMERA'}, {'10.10.12.203': 'IPC'}, {'10.10.12.209': 'OTHER DEVICES'}, {'10.10.12.242': 'CAMERA'}, {'10.10.12.246': 'IPC'}]


dvrlist = []
nvrlist = []
cameralist = []
ipclist = []
snortlist = []
otherdevicelist = []

for i in alldevice_list:
    if i.values()[0] == 'DVR':
        dvrlist.append(i)
    if i.values()[0] == 'NVR':
	nvrlist.append(i)
    if i.values()[0] == 'CAMERA':
        cameralist.append(i)
    if i.values()[0] == 'IPC':
	ipclist.append(i)
    if i.values()[0] == 'OTHER DEVICES':
	otherdevicelist.append(i)










