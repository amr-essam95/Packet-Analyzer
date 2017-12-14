# import scapy.all as scapy
import sys,re,json
from time import gmtime, strftime
sys.path.insert(0,'./scapy-master/')
import scapy.all as scapy
import scapy.utils as utils
from scapy.config import conf
from scapy.arch import linux

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
		# self.file = open('x','w')
		print linux.get_interfaces()

	def snif(self):
		pkts = scapy.sniff(iface=self.iface,filter=self.filter,count=self.cnt,prn=self.pkt_callback,store = 0)		
		# pkts = sniff(iface=self.iface,filter=self.filter,count=self.cnt,prn=self.pkt_callback,store = 0)		
	def pkt_callback(self,pkt):
		data =  self.pkt_parser(pkt)
		# self.file.write(json.dumps(data))

		self.window.addPacket(data)

	def content_parser(self,content):
		content = content.split("\n")
		content_dic = {}
		current_key = ""
		for line in content:
			# r = re.search("\\n",content)
			# print "xxxxxxxxxxxxxxxx"
			# print line.strip()
			# print "xxxxxxxxxxxxxxxx"
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
		r = re.search("(.*)\d",summary)
		if r:
			summary = r.group(1)
			protocol = summary.split("/")[-1].strip().split(" ")
		else:
			protocol = " "
		hex_output = utils.hexdump2(pkt)
		data = {"No.":self.counter}
		data["No."] = self.counter
		data["Time"] = strftime("%Y-%m-%d %H:%M:%S", gmtime())
		data["Protocol"] = protocol[0]
		if "IP" in pkt:
			data["Source"] = pkt["IP"].src
			data["Destination"] = pkt["IP"].dst
			# data["Protocol"] =  str(pkt["IP"].proto)
		else:
			data["Source"] = "-"
			data["Destination"] = "-"
			# data["Protocol"] = "-"
		data["Length"] = 0
		parsed_content = self.content_parser(content)
		if "Raw" in parsed_content:
			data["Info"] = parsed_content["Raw"].split("=")[1].strip().strip("'")
		else:
			data["Info"] = " "
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


