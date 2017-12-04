import PyQt4
from PyQt4 import QtGui, QtCore,uic
import socket
import sys
import threading
import time
import PacketCapture2 as capture
####################################################################
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
		# while True:
			#print("thread running")  #to test run function
		# time.sleep(self.interval)
		# packet= self.getPacket()
		# window.addPacket(packet)
		sniffer = capture.Sniffer(window = window)
		sniffer.snif()
	def getPacket(self):
		return {"No.":"1","Time":"15:10445454545454545454545454545","Source":"192.11.110.12","Destination":"192.10.11.11","Protocol":"http","Length":"1500","Info":"trial message blaaaaaaa","Description":{"bla":"blaa","ahmed":"lalaaa"},"Hexa":"00 55 66\nsjvisdj vsdnkvs vjdsnvj dsjvjsdv jsdsd vds vjsd vjk djvsd jv sdjv msd vds dv k vks\n vdsv \n"}
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
		self.startCaptureBtn.triggered.connect(lambda:self.startCaptureBtnClicked(self.startCaptureBtn))
		self.stopCaptureBtn.triggered.connect(lambda:self.stopCaptureBtnClicked(self.stopCaptureBtn))
		self.actionExitBtn.triggered.connect(lambda:self.exitBtnClicked(self.actionExitBtn))
		self.saveBtn.triggered.connect(lambda:self.saveBtnClicked(self.saveBtn))
		self.pauseCaptureBtn.triggered.connect(lambda:self.pauseCaptureBtnClicked(self.pauseCaptureBtn))
		self.packetList=[]
		self.filter=""
		self.tableSize=0
		self.stopped=False
		self.table.cellClicked.connect(self.cellCLicked)
		header = self.table.horizontalHeader()
		header.setResizeMode(QtGui.QHeaderView.ResizeToContents)
		header.setStretchLastSection(True)
		self.thread = ThreadingClass()
		#adjusting the filter
		#when selected add both descriptions
		#self.showPacketDescription(1)
######################################################
	def startCaptureBtnClicked(self,btn):
		if(self.stackedWidget.currentIndex()==0):
			#assure that connection is selected and send it to thread
			self.startCapture()
			self.stackedWidget.setCurrentIndex(1)
			self.startCaptureBtn.setEnabled(False)
			self.stopCaptureBtn.setEnabled(True)
			self.pauseCaptureBtn.setEnabled(True)
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
					self.pauseCaptureBtn.setEnabled(True)
					self.startCaptureBtn.setEnabled(False)
					self.stopCaptureBtn.setEnabled(True)
					self.startNewCapture("Ok")
				return
			self.pauseCaptureBtn.setEnabled(True)
			self.startCaptureBtn.setEnabled(False)
			self.stopCaptureBtn.setEnabled(True)
			self.startCapture()
#######################################################
	def cellCLicked(self,row,column):
		packet = [packet for packet in self.packetList if packet['No.'] == self.table.verticalHeaderItem(int(row)).text()][0]
		#packet = packet[0]
		self.showPacketDescription(packet)
		self.showPacketHexadecimal(packet)
		#find the packet
		#packet show description
		#packet show hexadecimal
#######################################################
	def stopCaptureBtnClicked(self,btn):      
		self.stopCapture()
		self.stopped=True
		self.startCaptureBtn.setEnabled(True)
		self.stopCaptureBtn.setEnabled(False)   
#########################################################
	def pauseCaptureBtnClicked(self,btn):      
		self.stopCapture()
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
		self.saveBtn.setEnabled(True)
#########################################################
	def stopCapture(self):
		self.thread.stop()
#########################################################
	def addPacket(self,packet):
		self.packetList.append(packet)
		filterOutput=self.passFilter(packet)
		if(filterOutput==True):
			self.addPacketToTable(packet)
#########################################################
	def addPacketToTable(self,packet):
		if packet!=None:
			print "entered add packet to table"
			print "the packet is "+str(packet)
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
		elif(str(packet['Protocol']).lower()==str(self.filter).lower()):
			return True
		else :
			return False
#########################################################
	def applyNewFilter(self):
		self.tableSize=0
		self.table.setRowCount(0)
		for packet in self.packetList:
			filterOutput=self.passFilter(packet)
			if (filterOutput==True):
				addPacketToTable(packet)
#########################################################
	def showPacketDescription(self,packet):
		self.treeWidget.clear()
		#packet={"No.":"1","Time":"15:10445454545454545454545454545","Source":"192.11.110.12","Destination":"192.10.11.11","Protocol":"http","Length":"1500","Info":"trial message blaaaaaaa","Description":{"bla":"blaa","ahmed":"lalaaa"},"Hexa":"00 55 66"}
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
		newFilter=self.filterLineEdit.text
		if (newFilter != self.filter):
			self.filter=newFilter
			self.applyNewFilter
#########################################################
	def saveSession(self):
		pass
#########################################################
	def saveBtnClicked(self,btn):
		pass
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
app = QtGui.QApplication(sys.argv)
window = MyWindow()
window.show()
app.exec_()
##########################################################



