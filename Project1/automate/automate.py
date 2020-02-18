import pyshark
import os

def get_org_name(ip):
    command = "whois " + pkt.ip.dst
    process = os.popen(command)
    result = str(process.read())
    marker1 = result.find('Organization:') + 16
    if marker1 > 16:
        marker2 = result.find('RegDate:')
        return result[marker1:marker2]
    else:
        return "unknown" + "\n"


in_name = input("Enter the File and Pathname of the input file: ")
fd1 = open(in_name, "r")

pcap = pyshark.FileCapture(fd1, display_filter='tls.handshake.type==1')
mylist = []

out_name = input("Enter the file name of the output file: ")
fd2 = open(out_name, "w")

for pkt in pcap:
    ip_src = str(pkt.ip.src)
    ip_dst = str(pkt.ip.dst)
    output = ip_src + "\t" +ip_dst + "\t" + pkt.tls.handshake_extensions_server_name + "\t" + get_org_name(pkt.ip.dst)
    mylist.append(output)

mylist = list(dict.fromkeys(mylist))
print(*mylist, file=fd2)
fd1.close()
fd2.close()
