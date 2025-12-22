
# inspired by this gist of Willi Ballenthin
# https://gist.github.com/williballenthin/277eedca569043ef0984

import idaapi


def get_QtCore():
    if idaapi.IDA_SDK_VERSION <= 680:
        # IDA 6.8 and below
        import PySide.QtCore as QtCore
        return QtCore
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        # IDA 6.9 - IDA 9.1
        import PyQt5.QtCore as QtCore
        return QtCore
    else:
        # IDA 9.2 and above
        import PySide6.QtCore as QtCore
        return QtCore


def get_QtGui():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtGui as QtGui
        return QtGui
    else:
        # IDA 9.2 and above
        import PySide6.QtGui as QtGui
        return QtGui


def get_QtWidgets():
    if idaapi.IDA_SDK_VERSION <= 680:
        return None
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets


def get_Qt():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtCore as QtCore
        return QtCore.Qt
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtCore as QtCore
        return QtCore.Qt
    else:
        # IDA 9.2 and above
        import PySide6.QtCore as QtCore
        return QtCore.Qt


def get_QTreeWidget():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QTreeWidget
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTreeWidget
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QTreeWidget


def get_QTreeWidgetItem():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QTreeWidgetItem
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTreeWidgetItem
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QTreeWidgetItem


def get_QHeaderView():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QHeaderView
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QHeaderView
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QHeaderView


def get_QCheckBox():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QCheckBox
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QCheckBox
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QCheckBox


def get_QIcon():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QIcon
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtGui as QtGui
        return QtGui.QIcon
    else:
        # IDA 9.2 and above
        import PySide6.QtGui as QtGui
        return QtGui.QIcon


def get_QWidget():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QWidget
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QWidget
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QWidget


def get_QVBoxLayout():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QVBoxLayout
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QVBoxLayout
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QVBoxLayout


def get_QHBoxLayout():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QHBoxLayout
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QHBoxLayout
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QHBoxLayout


def get_QGridLayout():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QGridLayout
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QGridLayout
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QGridLayout


def get_QSplitter():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QSplitter
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QSplitter
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QSplitter


def get_QStyleFactory():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QStyleFactory
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QStyleFactory
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QStyleFactory


def get_QStyleOptionSlider():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QStyleOptionSlider
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QStyleOptionSlider
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QStyleOptionSlider


def get_QApplication():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QApplication
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QApplication
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QApplication
def get_QPainter():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QPainter
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtGui as QtGui
        return QtGui.QPainter
    else:
        # IDA 9.2 and above
        import PySide6.QtGui as QtGui
        return QtGui.QPainter
    

def get_QPalette():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QPalette
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtGui as QtGui
        return QtGui.QPalette
    else:
        # IDA 9.2 and above
        import PySide6.QtGui as QtGui
        return QtGui.QPalette 


def get_DescendingOrder():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtCore as QtCore
        return QtCore.Qt.SortOrder.DescendingOrder
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtCore as QtCore
        return QtCore.Qt.DescendingOrder
    else:
        # IDA 9.2 and above
        import PySide6.QtCore as QtCore
        return QtCore.Qt.DescendingOrder


def get_QTabWidget():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QTabWidget
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTabWidget
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QTabWidget


def get_QStyle():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QStyle
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QStyle
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QStyle


def get_QLabel():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QLabel
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QLabel
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QLabel


def get_QTableWidget():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QTableWidget
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTableWidget
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QTableWidget
    
def get_QTableWidgetItem():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QTableWidgetItem
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTableWidgetItem
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QTableWidgetItem
    
def get_QStyledItemDelegate():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QStyledItemDelegate
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QStyledItemDelegate
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QStyledItemDelegate
    
def get_QPushButton():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QPushButton
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QPushButton
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QPushButton


def get_QAbstractItemView():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QAbstractItemView
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QAbstractItemView
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QAbstractItemView


def get_QScrollArea():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QScrollArea
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QScrollArea
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QScrollArea


def get_QSizePolicy():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QSizePolicy
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QSizePolicy
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QSizePolicy


def get_QLineEdit():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QLineEdit
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QLineEdit
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QLineEdit


def get_QCompleter():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QCompleter
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QCompleter
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QCompleter


def get_QTextBrowser():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QTextBrowser
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTextBrowser
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QTextBrowser


def get_QSlider():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QSlider
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QSlider
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QSlider


def get_QMainWindow():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QMainWindow
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QMainWindow
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QMainWindow


def get_QTextEdit():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QTextEdit
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTextEdit
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QTextEdit


def get_QDialog():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QDialog
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QDialog
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QDialog


def get_QGroupBox():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QGroupBox
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QGroupBox
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QGroupBox


def get_QRadioButton():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QRadioButton
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QRadioButton
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QRadioButton


def get_QStyledItemDelegate():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QStyledItemDelegate
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QStyledItemDelegate
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QStyledItemDelegate


def get_QComboBox():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QComboBox
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QComboBox
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QComboBox


def get_QCheckBox():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QCheckBox
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QCheckBox
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QCheckBox


def get_QAction():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QAction
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QAction
    else:
        # IDA 9.2 and above
        import PySide6.QtGui as QtGui
        return QtGui.QAction


def get_QBrush():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QBrush
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtGui as QtGui
        return QtGui.QBrush
    else:
        # IDA 9.2 and above
        import PySide6.QtGui as QtGui
        return QtGui.QBrush


def get_QColor():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QColor
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtGui as QtGui
        return QtGui.QColor
    else:
        # IDA 9.2 and above
        import PySide6.QtGui as QtGui
        return QtGui.QColor


def get_QStringListModel():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QStringListModel
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtCore as QtCore
        return QtCore.QStringListModel
    else:
        # IDA 9.2 and above
        import PySide6.QtCore as QtCore
        return QtCore.QStringListModel


def get_Signal():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtCore as QtCore
        return QtCore.Signal
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtCore as QtCore
        return QtCore.pyqtSignal
    else:
        # IDA 9.2 and above
        import PySide6.QtCore as QtCore
        return QtCore.Signal


def get_QFrame():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QFrame
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QFrame
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QFrame
    
def get_QFrameHLine():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QFrame.HLine
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QFrame.HLine
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QFrame.Shape.HLine
    
def get_QFrameShadow():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QFrame
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QFrame
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QFrame.Shadow


def get_QSpinBox():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QSpinBox
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QSpinBox
    else:
        # IDA 9.2 and above
        import PySide6.QtWidgets as QtWidgets
        return QtWidgets.QSpinBox

def get_QFont():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QFont
    elif 680 < idaapi.IDA_SDK_VERSION <= 910:
        import PyQt5.QtGui as QtGui
        return QtGui.QFont
    else:
        # IDA 9.2 and above
        import PySide6.QtGui as QtGui
        return QtGui.QFont