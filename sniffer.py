# import scapy.all as scapy
import sys,re,json
from time import gmtime, strftime
sys.path.insert(0,'./scapy-master/')
import scapy.all as scapy
import scapy.utils as utils
from scapy.config import conf
# from scapy.arch import linux
import scapy.data as dat
import datetime
import socket

"""
protocol need to be in string not number
if ip is not in the packet it's ipv6 and it's not handled
length is not handled yet
hexa_output is not handled yet

"""

class Sniffer(object):
	"""docstring for Sniffer"""
	def __init__(self,cnt = 0,filter = None,iface = None,store = 0,window=None):
		super(Sniffer, self).__init__()
		self.cnt = cnt
		self.filter = filter
		self.iface = iface
		self.counter = 0
		self.window = window
		self.c = 10
		self.MYTCP_SERVICES = {}
		for p in dat.TCP_SERVICES.keys():
			self.MYTCP_SERVICES[dat.TCP_SERVICES[p]] = p 
		# print linux.get_interfaces()

	def snif(self):
		pkts = scapy.sniff(iface=self.iface,filter=self.filter,count=self.cnt,prn=self.pkt_callback,store = 1,stop_filter=self.stopfilter)		
		return pkts
	def pkt_callback(self,pkt):
		data =  self.pkt_parser(pkt)
		self.window.addPacket(data)
	def stopfilter(self,pkt):
		if self.window.stop:
			return True
		return False

	def save(self,pkts,path = "pkts"):
		scapy.wrpcap(path+".pcap",pkts)
		# self.load(path+".pcap")

	def load(self,path = "pkts"):
		self.counter = 0
		# try:
		p = scapy.sniff(offline=path, prn=self.pkt_callback)
		# except:
			# print "Error in reading the pcap file"

	def content_parser(self,content):
		content = content.split("\n")
		content_dic = {}
		current_key = ""
		for line in content:
			r = re.search("###\[(.*)\]###",line)
			if r:
				current_key = r.group(1).strip()
				content_dic[current_key] =  ""
			else:
				content_dic[current_key] += line.strip() + "\n"				
		return content_dic

	def pkt_parser(self,pkt):
		self.counter += 1
		content = pkt.show(dump=True)
		summary = pkt.summary()
		r = re.search("(.*)(\d|Qry)",summary)
		# print summary
		if r:
			summary = r.group(1)
			protocol = summary.split("/")[-1].strip().split(" ")
			if re.search("IPv",protocol[0]):
				protocol[0] = "IPv6"
		else:
			protocol = " "
		hex_output = utils.hexdump2(pkt)
		data = {"No.":self.counter}
		data["No."] = self.counter
		data["Time"] = datetime.datetime.fromtimestamp(int(pkt.time)).strftime('%Y-%m-%d %H:%M:%S')
		data["Protocol"] = protocol[0]
		# if "Ether" in pkt:
		# 	data["Length"] = pkt["Ether"].len
		# else:
		# 	data["Length"] = 0
		if "IP" in pkt:
			data["Source"] = pkt["IP"].src
			data["Destination"] = pkt["IP"].dst
			data["Length"] = pkt["IP"].len
			# print socket.getservbyport(int(pkt["IP"].proto)),"--",protocol[0]
			# print str(pkt["IP"].proto)
			# print self.MYTCP_SERVICES[int(pkt["IP"].sport)]
			# data["Protocol"] =  str(pkt["IP"].proto)
		elif "IPv6" in pkt:
			data["Source"] = pkt["IPv6"].src
			data["Destination"] = pkt["IPv6"].dst
			data["Length"] = pkt["IPv6"].plen
		elif "ARP" in pkt:
			data["Source"] = pkt["ARP"].psrc
			data["Destination"] = pkt["ARP"].pdst
			data["Length"] = pkt["ARP"].plen
		else:
			data["Source"] = "-"
			data["Destination"] = "-"
			data["Length"] = 28
			# data["Protocol"] =  protocol[0]
		parsed_content = self.content_parser(content)
		if "Raw" in parsed_content:
			if re.search("GET|POST|HTTP",parsed_content["Raw"]):
				data["Info"] = parsed_content["Raw"].split("=")[1].strip().strip("'")
				temp = parsed_content["Raw"].split("=")[1].strip().strip("'").split('\\r\\n')
				temp_string = ""
				flag = True
				for x in temp:
					flag = False
					temp_string += x
					temp_string += "\n"
				parsed_content["HTTP"] = temp_string
				if flag:
					temp_string = data["Info"]

			else:
				data["Info"] = summary
				
		else:
			data["Info"] = summary
		if "UDP" in pkt:
			if str(pkt["UDP"].dport).strip() == "1900":
				data["Protocol"] = "ssdp"
		if re.search("^\d+.\d+.\d+.\d+",data["Protocol"]):
			data["Protocol"] = "IGMP"
		# r = re.search()
		data["Hexa"]  = hex_output
		data["Description"] = parsed_content
		return data


#set number of packets to be sniffed , if set to 0  it will be sniff to infinity 
cnt = 0
#set the Filter to any type of protocol , port etc. you want (ex.ICMP) ,None mean all
Filter = None
#set the device to sniff from (ex. eth0) , None mean all
iFace = None
#file name.pcap to print in it 
file_name="Mypackets"

# s = Sniffer(cnt,Filter,iFace)
# s.snif()


#for saving the packets sniffed to be viewed in wireshark or any same program
# scapy.wrpcap(file_name+".pcap",pkts)

#if you want to see packets be sniffed using wireshark or any same program uncomment the last 2 lines
#packets = rdpcap(file_name+".pcap")
#packets.show()


