#!/usr/bin/python
"""
MCRIT4IDA - integration with MCRIT server
code inspired by and based on IDAscope
"""
import os

import config
from helpers.ClassCollection import ClassCollection
from helpers.McritInterface import McritInterface
from widgets.MainWidget import MainWidget
from widgets.LocalInfoWidget import LocalInfoWidget
from widgets.SampleInfoWidget import SampleInfoWidget
from widgets.FunctionInfoWidget import FunctionInfoWidget

import helpers.QtShim as QtShim
QtGui = QtShim.get_QtGui()
QtCore = QtShim.get_QtCore()
QtWidgets = QtShim.get_QtWidgets()

import idc
import idaapi
from idaapi import PluginForm, plugin_t



################################################################################
# Core of the MCRIT4IDA GUI.
################################################################################

HOTKEYS = None
MCRIT4IDA = None
NAME = "MCRIT4IDA v%s" % config.VERSION


class Mcrit4IdaForm(PluginForm):
    """
    This class contains the main window of MCRIT4IDA
    Setup of core modules and widgets is performed in here.
    """

    def __init__(self):
        super(Mcrit4IdaForm, self).__init__()
        global HOTKEYS
        HOTKEYS = []
        self.cc = ClassCollection(QtShim)
        self.tabs = None
        self.parent = None
        self.config = config
        self.local_smda_report = {}
        self.matching_report = {}
        self.sample_infos = {}
        self.remote_function_mapping = {}
        self.remote_sample_id = None
        self.icon = self.cc.QIcon(config.ICON_FILE_PATH + "relationship.png")
        self.mcrit_interface = McritInterface(self)

    def getMatchingReport(self):
        return self.matching_report

    def getSampleInfos(self):
        return self.sample_infos

    def getFunctionInfos(self):
        return self.remote_function_mapping

    def getLocalSmdaReport(self):
        return self.local_smda_report

    def setupWidgets(self):
        """
        Setup MCRIT4IDA widgets.
        """
        time_before = self.cc.time.time()
        print("[/] setting up widgets...")
        self.local_widget = LocalInfoWidget(self)
        self.sample_widget = SampleInfoWidget(self)
        self.function_widget = FunctionInfoWidget(self)
        self.main_widget = MainWidget(self)
        # produce layout and render
        layout = self.cc.QVBoxLayout()
        layout.addWidget(self.main_widget)
        self.parent.setLayout(layout)
        print("[\\] this took %3.2f seconds.\n" % (self.cc.time.time() - time_before))

    def OnCreate(self, form):
        """
        When creating the form, setup the shared modules and widgets
        """
        print ("[+] Loading MCRIT4IDA")
        # compatibility with IDA < 6.9
        try:
            self.parent = self.FormToPySideWidget(form)
        except Exception as exc:
            self.parent = self.FormToPyQtWidget(form)
        self.parent.setWindowIcon(self.icon)
        self.setupWidgets()

    def OnClose(self, form):
        """
        Perform cleanup.
        """
        global MCRIT4IDA
        del MCRIT4IDA

    def Show(self):
        if self.cc.ida_proxy.GetInputMD5() is not None:
            return PluginForm.Show(self, NAME, options=(PluginForm.WCLS_CLOSE_LATER | PluginForm.WOPN_RESTORE | PluginForm.WCLS_SAVE))
        return None

################################################################################
# functionality offered to MCRIT4IDA's widgets
################################################################################

    def registerHotkey(self, shortcut, py_function_pointer):
        """
        Can be used by MCRIT4IDA widgets to register hotkeys.
        Uses a global list HOTKEYS of function pointers that link to the desired functionality.
        Right now, linked functions cannot take parameters and should scrape all information they need by themselves.
        @param shortcut: A string describing a shortcut, e.g. "ctrl+F3"
        @type shortcut: str
        @param py_function_pointer: a python function that shall be called when the shortcut is triggered.
        @type py_function_pointer: a pointer to a python function
        """
        global HOTKEYS
        hotkey_index = len(HOTKEYS)
        hotkey_name = "MCRIT4IDA_HOTKEY_%d" % hotkey_index
        HOTKEYS.append(py_function_pointer)
        self.cc.ida_proxy.CompileLine('static %s() { RunPythonStatement("HOTKEYS[%d]()"); }' % (hotkey_name, hotkey_index))
        self.cc.ida_proxy.AddHotkey(shortcut, hotkey_name)

################################################################################
# Usage as plugin
################################################################################


def PLUGIN_ENTRY():
    return Mcrit4IdaPlugin()


class Mcrit4IdaPlugin(plugin_t):
    """
    Plugin version of MCRIT4IDA. Use this to deploy MCRIT4IDA via IDA plugins folder.
    """
    flags = idaapi.PLUGIN_UNL
    comment = NAME
    help = "MCRIT4IDA - Plugin to interact with a MCRIT server."
    wanted_name = "MCRIT4IDA"
    wanted_hotkey = "Ctrl-F4"

    def init(self):
        # Some initialization
        self.icon_id = 0
        return idaapi.PLUGIN_OK

    def run(self, arg=0):
        # Create form
        f = Mcrit4IdaForm()
        # Show the form
        f.Show()
        return

    def term(self):
        pass

################################################################################
# Usage as script
################################################################################


def main():
    global MCRIT4IDA
    try:
        MCRIT4IDA.OnClose(MCRIT4IDA)
        print("reloading MCRIT4IDA")
        MCRIT4IDA = Mcrit4IdaForm()
        return
    except Exception:
        MCRIT4IDA = Mcrit4IdaForm()

    if config.MCRIT4IDA_PLUGIN_ONLY:
        print("MCRIT4IDA: configured as plugin-only mode, ignoring main function of script.")
    else:
        MCRIT4IDA.Show()


if __name__ == "__main__":
    main()
