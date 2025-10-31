import json
import os
import sys
import time
import re
from collections import deque

import helpers.QtShim as QtShim

from helpers.IdaProxy import IdaProxy


class ClassCollection():

    def __init__(self, shim):
        # python imports
        self.json = json
        self.os = os
        self.os_path = os.path
        self.re = re
        self.sys = sys
        self.time = time
        self.deque = deque
        # PySide / PyQt imports
        self.QtShim = shim
        self.QtGui = self.QtShim.get_QtGui()
        self.QtCore = self.QtShim.get_QtCore()
        self.QIcon = self.QtShim.get_QIcon()
        self.QWidget = self.QtShim.get_QWidget()
        self.QVBoxLayout = self.QtShim.get_QVBoxLayout()
        self.QHBoxLayout = self.QtShim.get_QHBoxLayout()
        self.QGridLayout = self.QtShim.get_QGridLayout()
        self.QSplitter = self.QtShim.get_QSplitter()
        self.QStyleFactory = self.QtShim.get_QStyleFactory()
        self.QLabel = self.QtShim.get_QLabel()
        self.QTableWidget = self.QtShim.get_QTableWidget()
        self.QAbstractItemView = self.QtShim.get_QAbstractItemView()
        self.QTableWidgetItem = self.QtShim.get_QTableWidgetItem()
        self.QStyledItemDelegate = self.QtShim.get_QStyledItemDelegate()
        self.QPushButton = self.QtShim.get_QPushButton()
        self.QScrollArea = self.QtShim.get_QScrollArea()
        self.QSizePolicy = self.QtShim.get_QSizePolicy()
        self.QLineEdit = self.QtShim.get_QLineEdit()
        self.QTextEdit = self.QtShim.get_QTextEdit()
        self.QMainWindow = self.QtShim.get_QMainWindow()
        self.QSlider = self.QtShim.get_QSlider()
        self.QCompleter = self.QtShim.get_QCompleter()
        self.QTextBrowser = self.QtShim.get_QTextBrowser()
        self.QStringListModel = self.QtShim.get_QStringListModel()
        self.QDialog = self.QtShim.get_QDialog()
        self.QGroupBox = self.QtShim.get_QGroupBox()
        self.QRadioButton = self.QtShim.get_QRadioButton()
        self.QComboBox = self.QtShim.get_QComboBox()
        self.QCheckBox = self.QtShim.get_QCheckBox()
        self.QAction = self.QtShim.get_QAction()
        self.QColor = self.QtShim.get_QColor()
        self.QBrush = self.QtShim.get_QBrush()
        self.QPalette = self.QtShim.get_QPalette()
        self.QTreeWidget = self.QtShim.get_QTreeWidget()
        self.QTreeWidgetItem = self.QtShim.get_QTreeWidgetItem()
        self.QStyle = self.QtShim.get_QStyle()
        self.QPainter = self.QtShim.get_QPainter()
        self.QApplication = self.QtShim.get_QApplication()
        self.QStyleOptionSlider = self.QtShim.get_QStyleOptionSlider()
        self.QTabWidget = self.QtShim.get_QTabWidget()
        self.DescendingOrder = self.QtShim.get_DescendingOrder()
        self.QFrame = self.QtShim.get_QFrame()
        self.QSpinBox = self.QtShim.get_QSpinBox()
        self.QFont = self.QtShim.get_QFont()
        # ida_proxy
        self.ida_proxy = IdaProxy()
