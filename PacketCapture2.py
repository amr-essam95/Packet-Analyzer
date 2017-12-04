'''

This will be Example for using scapy for sniffing a packets

'''

import scapy.all as scapy
import json,sys
import jsonpickle
import io



#CONFIG

class Sniffer(object):
	"""docstring for Sniffer"""
	def __init__(self,cnt = 0,filter = None,iface = None,store = 0):
		super(Sniffer, self).__init__()
		self.cnt = cnt
		self.filter = filter
		self.iface = iface

	def snif(self):
		pkts = scapy.sniff(iface=self.iface,filter=self.filter,count=self.cnt,prn=self.pkt_callback,store = 0)		

	def pkt_callback(self,pkt):
		self.pkt_parser(pkt)

	def pkt_parser(self,pkt):
		content = pkt.show(dump=True)
		summary = pkt.summary()

		# qsave = sys.stdout
		q = io.StringIO() 

		#CAPTURES OUTPUT
		sys.stdout = q  

		#Text you're capturing
		scapy.hexdump(pkt)

		#restore original stdout
		# sys.stdout = qsave

		#release output
		# sout = q.getvalue()

		#Add to string (format if need be)
		# outputPacket += sout + '\n'

		#Close IOStream
		# q.close() 
		print "ooooooooooooooo"
		# print outputPacket
		print "hhhhhhhhhhhhhhhhh"
		# print summary
		# print x
		print "\n\n"
	def expand(self,x):
		yield x
		while x.payload:
			x = x.payload
			yield x

#set number of packets to be sniffed , if set to 0  it will be sniff to infinity 
cnt = 0

#set the Filter to any type of protocol , port etc. you want (ex.ICMP) ,None mean all
Filter = None

#set the device to sniff from (ex. eth0) , None mean all
iFace = None

#file name.pcap to print in it 
file_name="Mypackets"

#END CONFIG

# def pkt_callback(pkt):
# 	print "hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh"
# 	pkt.show()


#For live sniffing of packets and printing summary about each packet sniffed
# pkts = scapy.sniff(iface=iFace,filter=Filter,count=cnt,prn=pkt_callback,store = 0)
# pkts = scapy.sniff(iface=iFace,filter=Filter,count=cnt,prn=lambda x:x.sprintf("{IP:%IP.src% -> %IP.dst%\n}{Raw:%Raw.load%\n}"))

s = Sniffer(cnt,Filter,iFace)
s.snif()

#for details of packets to be shown 
# for i in range(len(pkts)):
# 	print("\n\n")	
# 	print(pkts[i].show())			
	

# print("\n\n")
#for expressing content of each packet in hex
# for i in range(len(pkts)):
# 	print("\n")
# 	print(scapy.hexdump(pkts[i]))


# print("\n")


#for saving the packets sniffed to be viewed in wireshark or any same program
# scapy.wrpcap(file_name+".pcap",pkts)

#if you want to see packets be sniffed using wireshark or any same program uncomment the last 2 lines
#packets = rdpcap(file_name+".pcap")
#packets.show()


