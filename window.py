import PyQt4
from PyQt4 import QtGui, QtCore,uic
import socket
import sys


qtCreatorFile="NetworkAnalyzer.ui"
Ui_MainWindow,QtBaseClass = uic.loadUiType(qtCreatorFile) 

###############################
class MyWindow(QtGui.QMainWindow,Ui_MainWindow):    # any super class is okay
	def __init__(self, parent=None):
		QtGui.QMainWindow.__init__(self)
		Ui_MainWindow.__init__(self)
		self.setupUi(self)
		self.setWindowState(QtCore.Qt.WindowMaximized)
		self.startCaptureBtn.triggered.connect(lambda:self.startCaptureBtnClicked(self.startCaptureBtn))
		self.stopCaptureBtn.triggered.connect(lambda:self.stopCaptureBtnClicked(self.stopCaptureBtn))
		self.packetList=[]
		self.filter=""
######################################################
	def startCaptureBtnClicked(self,btn):
	  
		if(self.stackedWidget.currentIndex()==0):
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
		pass
#########################################################
	def stopCapture(self):
		pass
#########################################################
	def addEntry(self):
		pass
#########################################################
	def addPacket(self,packet):
		self.packetList.append(packet)
#########################################################
	def addPacketToTable(self,packet):
		pass
#########################################################
	def filterPacket(self,packet):
		pass
#########################################################
	def applyNewFilter(self):
		pass
#########################################################
	def showPacketDescription(self,packet):
		pass
#########################################################
	def showPacketHexadecimal(self,packet):
		pass
#########################################################
	def applyFilterClicked(self,btn):
		pass
#########################################################
	def saveSession(self):
		pass
#########################################################
	def saveBtnClicked(self,btn):
		pass
#########################################################
	def exitBtnClicked(self,btn):
		pass
#########################################################
	def exitProgram(self):
		pass
app = QtGui.QApplication(sys.argv)
window = MyWindow()
window.show()
app.exec_()
##########################################################
import threading
import time
class ThreadingClass(QtCore.QThread):

	""" Threading example class
	The run() method will be started and it will run in the background
	until the application exits.
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
		thread.start() # Start the execution
	def run(self):
		""" Method that runs forever """
		while True:
			time.sleep(self.interval)
			packet= self.getPacket()
			window.addPacket(packet)
	def getPacket(self):
		pass

thread = ThreadingClass()
##############################################################


