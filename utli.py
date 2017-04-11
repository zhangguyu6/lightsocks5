#-*- coding: utf-8 -*-
def parseaddr(addrtype,data):
    if addrtype == 1:
        host, port,index= data[4:8], data[8:10],10
    elif addrtype == 3:
        hostlength = data[4]
        host, port,index = data[5:5 + hostlength], data[5 + hostlength:7+ hostlength],7+ hostlength
    elif addrtype == 4:
        host, port,index = data[4:20], data[20:22],22
    return host,port,index

def decript_data(self, datas):
    encript_data = []

    for data in datas:
        data = chr(ord(data) ^ 0x12)
        encript_data.append(data)

    return b"".join(encript_data)

def encript_data(self, datas):
    decript_data = []

    for data in datas:
        data = chr(ord(data) ^ 0x12)
        decript_data.append(data)

    return b"".join(decript_data)

import yaml
a=yaml.load(open("test.yaml"))
