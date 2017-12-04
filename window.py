import PyQt4
from PyQt4 import QtGui, QtCore,uic
import socket
import sys
import threading
import time
####################################################################
class ThreadingClass(QtCore.QThread):
	""" Threading example class
	The run() method will be started and it will run in the background
	until the method stop is called.
	"""
	def __init__(self, interval=5):
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
		while True:
			#print("thread running")  #to test run function
			time.sleep(self.interval)
			packet= self.getPacket()
			window.addPacket(packet)
	def getPacket(self):
		return {"No.":"1","Time":"15:10445454545454545454545454545","Source":"192.11.110.12","Destination":"192.10.11.11","Protocol":"http","Length":"1500","Info":"trial message blaaaaaaa","Description":{"bla":"blaa"},"Hexa":"00 55 66"}
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
		self.packetList=[]
		self.filter=""
		self.tableSize=0
		header = self.table.horizontalHeader()
		header.setResizeMode(QtGui.QHeaderView.ResizeToContents)
		header.setStretchLastSection(True)
		self.thread = ThreadingClass()
######################################################
	def startCaptureBtnClicked(self,btn):
		if(self.stackedWidget.currentIndex()==0):
			#assure that connection is selected and send it to thread
			self.startCapture()
			self.stackedWidget.setCurrentIndex(1)
			self.startCaptureBtn.setEnabled(False)
			self.stopCaptureBtn.setEnabled(True)
		else:
			self.startCaptureBtn.setEnabled(False)
			self.stopCaptureBtn.setEnabled(True)
			self.startCapture()
#######################################################
	def stopCaptureBtnClicked(self,btn):      
		self.stopCapture()
		self.startCaptureBtn.setEnabled(True)
		self.stopCaptureBtn.setEnabled(False)   
#########################################################
	def startCapture(self):
		self.thread.start()
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
		for key, value in packet['Description'].iteritems():
			#fill the tree
			pass
#########################################################
	def showPacketHexadecimal(self,packet):
		self.plainTextEdit.setText(packet['Hexa'])
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
		msg.buttonClicked.connect(self.exitProgram)
		retval = msg.exec_()
		if retval==QtGui.QMessageBox.Ok:
			self.exitProgram
#########################################################
	def exitProgram(self,buttonPressed):
			sys.exit()
#########################################################
app = QtGui.QApplication(sys.argv)
window = MyWindow()
window.show()
app.exec_()
##########################################################



