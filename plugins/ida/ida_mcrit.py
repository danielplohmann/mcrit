#!/usr/bin/python
"""
MCRIT4IDA - integration with MCRIT server
code inspired by and based on IDAscope
"""
import os

from smda.common.SmdaReport import SmdaReport

import config
from helpers.ClassCollection import ClassCollection
from helpers.McritInterface import McritInterface
from widgets.MainWidget import MainWidget
from widgets.LocalInfoWidget import LocalInfoWidget
from widgets.FunctionMatchWidget import FunctionMatchWidget
from widgets.BlockMatchWidget import BlockMatchWidget
from widgets.SampleInfoWidget import SampleInfoWidget
from widgets.FunctionOverviewWidget import FunctionOverviewWidget

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

G_FORM = None


class IdaViewHooks(idaapi.View_Hooks):
    """
    Courtesy of Alex Hanel's FunctionTrapperKeeper
    https://github.com/alexander-hanel/FunctionTrapperKeeper/blob/main/function_trapper_keeper.py
    """
    def view_curpos(self, view):
        self.refresh_widget(view)

    def view_dblclick(self, view, event):
        self.refresh_widget(view)

    def view_click(self, view, event):
        self.refresh_widget(view)

    def view_loc_changed(self, view, now, was):
        self.refresh_widget(view)

    def refresh_widget(self, view):
        global G_FORM
        for widget in G_FORM.hook_subscribed_widgets:
            widget.hook_refresh(view)


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
        #### local state used to populate and exchange information across widgets
        self.remote_sample_id = None
        self.remote_sample_entry = None
        self.local_smda_report = None
        # the smda_report without xcfg part
        self.local_smda_report_outline = None
        # after selecting a finished remote job, this is the cached data
        self.matching_job_id = None
        self.matching_report = None
        self.matched_function_entries = None
        # cached function matches that result from Function Scope queries
        self.current_block = None
        self.current_function = None
        self.function_matches = {}
        # offset to PicBlockHash
        self.block_to_hash = {}
        # PicBlockHash to matches from remote server
        self.blockhash_matches = {}
        # unused
        self.remote_function_mapping = {}
        self.sample_infos = {}
        self.family_infos = None
        self.pichash_matches = {}
        self.pichash_match_summaries = {}
        self.picblockhash_matches = {}
        ##### some more setup
        self.icon = self.cc.QIcon(config.ICON_FILE_PATH + "relationship.png")
        self.mcrit_interface = McritInterface(self)
        self.hook_subscribed_widgets = []

    def getMatchingReport(self):
        return self.matching_report

    def getSampleInfos(self):
        return self.sample_infos

    def getFunctionInfos(self):
        return self.remote_function_mapping

    def getLocalSmdaReport(self):
        return self.local_smda_report

    def getLocalSmdaReportOutline(self):
        if self.local_smda_report_outline is None and self.local_smda_report:
            report_as_dict = self.local_smda_report.toDict()
            report_as_dict["xcfg"] = {}
            self.local_smda_report_outline = SmdaReport.fromDict(report_as_dict)
        return self.local_smda_report_outline

    def setupWidgets(self):
        """
        Setup MCRIT4IDA widgets.
        """
        time_before = self.cc.time.time()
        print("[/] setting up widgets...")
        self.local_widget = LocalInfoWidget(self)
        self.block_match_widget = BlockMatchWidget(self)
        self.function_match_widget = FunctionMatchWidget(self)
        self.sample_widget = SampleInfoWidget(self)
        self.function_widget = FunctionOverviewWidget(self)
        self.main_widget = MainWidget(self)
        self.hook_subscribed_widgets.append(self.function_match_widget)
        self.hook_subscribed_widgets.append(self.block_match_widget)
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
        self.ViewHook = IdaViewHooks()
        self.ViewHook.hook()
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
        global G_FORM
        G_FORM = f
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
        global G_FORM
        G_FORM = MCRIT4IDA
        MCRIT4IDA.Show()


if __name__ == "__main__":
    main()
