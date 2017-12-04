'''

This will be Example for using scapy for sniffing a packets

'''

import scapy.all as scapy


#CONFIG


#set number of packets to be sniffed , if set to 0  it will be sniff to infinity 
cnt = 4

#set the Filter to any type of protocol , port etc. you want (ex.ICMP) ,None mean all
Filter = None

#set the device to sniff from (ex. eth0) , None mean all
iFace = None

#file name.pcap to print in it 
file_name="Mypackets"

#END CONFIG


#For live sniffing of packets and printing summary about each packet sniffed
pkts = scapy.sniff(iface=iFace,filter=Filter,count=cnt,prn = lambda x: x.summary())


#for details of packets to be shown 
for i in range(len(pkts)):
	print("\n\n")	
	print(pkts[i].show())			
	

print("\n\n")
#for expressing content of each packet in hex
for i in range(len(pkts)):
	print("\n")
	print(scapy.hexdump(pkts[i]))


print("\n")


#for saving the packets sniffed to be viewed in wireshark or any same program
scapy.wrpcap(file_name+".pcap",pkts)

#if you want to see packets be sniffed using wireshark or any same program uncomment the last 2 lines
#packets = rdpcap(file_name+".pcap")
#packets.show()


