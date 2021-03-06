import PyQt4
from PyQt4 import QtGui, QtCore,uic
import socket
import sys
import threading
import time
import sniffer as capture
sys.path.insert(0,'./scapy-master/')
import scapy.all as scapy
from scapy.all import conf
# from scapy.arch import linux
####################################################################

def get_int():
	try:
		import scapy.arch.windows as x
		interfaces = x.get_windows_interfaces()
		interfaces_list = []
		interfaces_dic = {}
		for interface in interfaces:
			state,dev = x.dev_from_index2(interface['win_index'])
			if state:
				interfaces_list.append(interface['name'])
				interfaces_dic[interface['name']] = dev
		return interfaces_list,interfaces_dic
	except:
		pass
	try:
		from scapy.arch import linux
		return linux.get_interfaces()
	except:
		print "Problem with OS"
		sys.exit()

class ThreadingClass(QtCore.QThread):
	""" Threading example class
	The run() method will be started and it will run in the background
	until the method stop is called.
	"""
	def __init__(self, interval=1):
		""" Constructor
		:type interval: int
		:param interval: Check interval, in seconds
		"""
		QtCore.QThread.__init__(self, parent=None)
		#threading.Thread.__init__(self, *args, **kwargs)
		self.interval = interval
		thread = threading.Thread(target=self.run, args=())
		self.signal = QtCore.SIGNAL("signal")
		thread.daemon = True # Daemonize thread
		#thread.start() # Start the execution
		#print("thread started")
		self._stop_event = threading.Event()

	def run(self):
		""" Method that runs forever """
		if window.selectedDevice == None:
			device = None
		else:
			device = dic_devices[str(window.selectedDevice)]
		window.sniffer = capture.Sniffer(iface = device, window = window)
		window.scapy_packets = window.sniffer.snif()
		print window.scapy_packets
		window.stop = False

	def stop(self):
		window.thread.terminate()
		#print("thread stopped")  #to test stop function
#################################################################
qtCreatorFile="NetworkAnalyzer.ui"
Ui_MainWindow,QtBaseClass = uic.loadUiType(qtCreatorFile) 
#######################################################
class MyWindow(QtGui.QMainWindow,Ui_MainWindow):    # any super class is okay
	def __init__(self, parent=None):
		QtGui.QMainWindow.__init__(self)
		Ui_MainWindow.__init__(self)
		self.setupUi(self)
		self.setWindowState(QtCore.Qt.WindowMaximized)
		self.addDevicesToList()
		self.startCaptureBtn.triggered.connect(lambda:self.startCaptureBtnClicked(self.startCaptureBtn))
		self.stopCaptureBtn.triggered.connect(lambda:self.stopCaptureBtnClicked(self.stopCaptureBtn))
		self.actionExitBtn.triggered.connect(lambda:self.exitBtnClicked(self.actionExitBtn))
		self.applyFIlterBtn.clicked.connect(lambda:self.applyFilterClicked(self.applyFIlterBtn))
		self.saveBtn.triggered.connect(lambda:self.saveBtnClicked(self.saveBtn))
		self.loadBtn.triggered.connect(lambda:self.fileOpen(self.loadBtn))
		self.pauseCaptureBtn.triggered.connect(lambda:self.pauseCaptureBtnClicked(self.pauseCaptureBtn))
		self.packetList=[]
		self.filter=""
		self.tableSize=0
		self.stopped=False
		self.table.cellClicked.connect(self.cellCLicked)
		header = self.table.horizontalHeader()
		header.setResizeMode(QtGui.QHeaderView.ResizeToContents)
		header.setStretchLastSection(True)
		self.treeWidget.header().setResizeMode(QtGui.QHeaderView.ResizeToContents)
		self.treeWidget.header().setStretchLastSection(False)
		self.thread = ThreadingClass()
		self.selectedDevice=None
		self.stop=False
		self.scapy_packets = None
		self.sniffer = None
		# treeheader = self.treeWidget.horizontalHeader()
		# treeheader.setResizeMode(QtGui.QHeaderView.ResizeToContents)
		#adjusting the filter
		#when selected add both descriptions
		#self.showPacketDescription(1)
######################################################
	def startCaptureBtnClicked(self,btn):
		self.pauseCaptureBtn.setEnabled(False)
		if(self.stackedWidget.currentIndex()==0):
			#assure that connection is selected and send it to thread
			if self.listWidget.currentItem()==None :
				self.selectedDevice = None
				#print self.selectedDevice
			else:
				self.selectedDevice= self.listWidget.currentItem().text()
				#print self.selectedDevice
			self.startCapture()
			self.loadBtn.setEnabled(False)
			self.stackedWidget.setCurrentIndex(1)
			self.startCaptureBtn.setEnabled(False)
			self.stopCaptureBtn.setEnabled(True)
			# self.pauseCaptureBtn.setEnabled(True)
		else:
			if(self.stopped==True):
				#message to confirm that he will lose the data if he didn't save session
				msg = QtGui.QMessageBox()
				msg.setIcon(QtGui.QMessageBox.Information)
				msg.setText("Starting capture without saving will cause loss of last session data")
				#msg.setInformativeText("By pressing ok the program will be closed")
				msg.setWindowTitle("Starting capture")
				#msg.setDetailedText("Are you sure dude?")
				msg.setStandardButtons(QtGui.QMessageBox.Ok | QtGui.QMessageBox.Cancel)
				msg.buttonClicked.connect(self.startNewCapture)
				retval = msg.exec_()
				if retval==QtGui.QMessageBox.Ok:
					# self.pauseCaptureBtn.setEnabled(True)
					self.startCaptureBtn.setEnabled(False)
					self.stopCaptureBtn.setEnabled(True)
					self.startNewCapture("Ok")
				return
			self.loadBtn.setEnabled(False)
			# self.pauseCaptureBtn.setEnabled(True)
			self.startCaptureBtn.setEnabled(False)
			self.stopCaptureBtn.setEnabled(True)
			self.startCapture()
#######################################################
	def addDevicesToList(self):
		devicesList = []
		# devicesList,dic = linux.get_interfaces()
		devicesList,devicesdic = get_int()
		for item in devicesList:
			self.listWidget.addItem(QtGui.QListWidgetItem(item))
	
########################################################

	def cellCLicked(self,row,column):
		# print row
		# print column
		# print self.packetList
		# print self.table.verticalHeaderItem(int(row)).text()

		packet = [packet for packet in self.packetList if str(packet['No.']) == self.table.verticalHeaderItem(int(row)).text()]
		packet = packet[0]
		self.showPacketDescription(packet)
		self.showPacketHexadecimal(packet)
		#find the packet
		#packet show description
		#packet show hexadecimal
#######################################################
	def stopCaptureBtnClicked(self,btn):      
		self.stopCapture()
		self.stopped=True
		self.saveBtn.setEnabled(True)
		self.loadBtn.setEnabled(True)
		self.startCaptureBtn.setEnabled(True)
		self.stopCaptureBtn.setEnabled(False) 
		self.pauseCaptureBtn.setEnabled(False)  
#########################################################
	def pauseCaptureBtnClicked(self,btn):      
		self.stopCapture()
		self.saveBtn.setEnabled(True)
		self.loadBtn.setEnabled(True)
		self.pauseCaptureBtn.setEnabled(False)
		self.startCaptureBtn.setEnabled(True)
		self.stopCaptureBtn.setEnabled(True) 
#########################################################
	def startNewCapture(self,btn):
		if (btn=="Ok"):
			self.packetList=[]
			self.table.setRowCount(0)
			self.tableSize=0
			self.startCapture()
#########################################################
	def startCapture(self):
		self.stopped=False
		self.thread.start()
		self.saveBtn.setEnabled(False)
#########################################################
	def stopCapture(self):
		self.stop = True
		#self.thread.stop()
#########################################################
	def addPacket(self,packet):
		self.packetList.append(packet)
		filterOutput=self.passFilter(packet)
		if(filterOutput==True):
			self.addPacketToTable(packet)
#########################################################
	def addPacketToTable(self,packet):

		if packet!=None:
			#print "entered add packet to table"
			# print "entered add packet to table"
			# print "the packet is "+str(packet)
			self.table.insertRow(self.tableSize)
			self.table.setVerticalHeaderItem(self.tableSize, QtGui.QTableWidgetItem(str(packet["No."])))
			#self.table.setItem(self.tableSize,0, QtGui.QTableWidgetItem(str(packet['No.'])))
			self.table.setItem(self.tableSize,0, QtGui.QTableWidgetItem(str(packet['Time'])))
			self.table.setItem(self.tableSize,1, QtGui.QTableWidgetItem(str(packet['Source'])))
			self.table.setItem(self.tableSize,2, QtGui.QTableWidgetItem(str(packet['Destination'])))
			self.table.setItem(self.tableSize,3, QtGui.QTableWidgetItem(str(packet['Protocol'])))
			self.table.setItem(self.tableSize,4, QtGui.QTableWidgetItem(str(packet['Length'])))
			self.table.setItem(self.tableSize,5, QtGui.QTableWidgetItem(str(packet['Info'])))
			#self.table.resizeColumnsToContents()
			self.tableSize += 1
#########################################################
	def passFilter(self,packet):
		if (self.filter==""):#if there is no filter
			return True
		else:
			columns=['Time','Source','Destination','Protocol','Length','Info']
			for column in columns:
				if (str(packet[column]).lower() == str(self.filter).lower()):
					return True
		
		return False
#########################################################
	def applyNewFilter(self):
		#print "entered apply new filter"
		self.tableSize=0
		self.table.setRowCount(0)
		#print "the packetlist I am looping on is "
		#print "###################################"
		#print str(self.packetList)
		for packet in self.packetList:
			
			filterOutput=self.passFilter(packet)
			#print "****************************"
			#print "the packet is "+ str(packet)
			#print "the filter output is " + str(filterOutput)
			if (filterOutput==True):
				self.addPacketToTable(packet)
#########################################################
	def showPacketDescription(self,packet):
		self.treeWidget.clear()
		for key,value in packet['Description'].iteritems():
			itemKey = QtGui.QTreeWidgetItem([key])
			self.treeWidget.addTopLevelItem(itemKey)
			itemValue = QtGui.QTreeWidgetItem([value])
			itemKey.addChild(itemValue)
			
#########################################################
	def showPacketHexadecimal(self,packet):
		self.plainTextEdit.clear()
		self.plainTextEdit.appendPlainText(packet['Hexa'])
#########################################################
	def applyFilterClicked(self,btn):
		#print "ok I am clicked"
		newFilter=self.filterLineEdit.text()
		#print "the text of the filter was " + str(self.filter)
		if (newFilter != self.filter):

			self.filter=newFilter
			#print "the text of the filter became " + str(self.filter)
			self.applyNewFilter()
#########################################################
	def saveBtnClicked(self,btn):
		fileName= QtGui.QFileDialog.getSaveFileName(self, 'Save File')
		if (str(fileName) != ""):
			self.sniffer.save(self.scapy_packets,str(fileName))
			print "Saved object is %s and is saved in %s.pcap" % (self.scapy_packets,fileName)


		# self.clearTable()
		# file = open(fileName,'w')
#########################################################
	def fileOpen(self,btn):
		fileName= QtGui.QFileDialog.getOpenFileName(self,'open File')
		if (str(fileName) != ""):
			self.pauseCaptureBtn.setEnabled(False)
			self.startCaptureBtn.setEnabled(True)
			self.stopCaptureBtn.setEnabled(False)
			self.stopped=True
			if (self.stackedWidget.currentIndex()==0):
				self.stackedWidget.setCurrentIndex(1)
			self.clearTable()
			print str(fileName)
			self.sniffer = capture.Sniffer(window = window)
			try:
				self.sniffer.load(str(fileName))
			except:
				print "Error While loading"

	def clearTable(self):
		self.packetList=[]
		self.table.setRowCount(0)
		self.tableSize=0
		
#########################################################
	# def saveSession(self):
	# 	pass
#########################################################
	
#########################################################
	def exitBtnClicked(self,btn):
		msg = QtGui.QMessageBox()
		msg.setIcon(QtGui.QMessageBox.Information)
		msg.setText("Are you sure you want to exit?")
		#msg.setInformativeText("By pressing ok the program will be closed")
		msg.setWindowTitle("Exit Window")
		msg.setDetailedText("Are you sure dude?")
		msg.setStandardButtons(QtGui.QMessageBox.Ok | QtGui.QMessageBox.Cancel)
		#msg.buttonClicked.connect(self.exitProgram)
		retval = msg.exec_()
		if retval==QtGui.QMessageBox.Ok:
			self.exitProgram("ok")
#########################################################
	def exitProgram(self,buttonPressed):
		if buttonPressed =="ok":
			sys.exit()
#########################################################

		# print (dir(conf.iface))
		# print (conf.iface)
	
app = QtGui.QApplication(sys.argv)
# ldev,dic_devices = linux.get_interfaces()
ldev,dic_devices = get_int()
list_of_packets = []
app.setStyle('plastique')
window = MyWindow()
window.show()

app.exec_()
##########################################################


