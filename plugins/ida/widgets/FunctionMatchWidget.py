import idaapi
import ida_funcs
import ida_kernwin

import helpers.QtShim as QtShim
QMainWindow = QtShim.get_QMainWindow()
from widgets.NumberQTableWidgetItem import NumberQTableWidgetItem


class FunctionMatchWidget(QMainWindow):

    def __init__(self, parent):
        self.cc = parent.cc
        self.cc.QMainWindow.__init__(self)
        print("[|] loading FunctionMatchWidget")
        # enable access to shared MCRIT4IDA modules
        self.parent = parent
        self.name = "Function Match Overview"
        self.last_family_selected = None
        self.icon = self.cc.QIcon(self.parent.config.ICON_FILE_PATH + "flag-triangle.png")
        self.central_widget = self.cc.QWidget()
        self.setCentralWidget(self.central_widget)
        self.label_current_pichash_matches = self.cc.QLabel("PicHash Matches for Function: <function_offset>")
        self.cb_filter_library = self.cc.QCheckBox("Filter out Library Matches")
        self.cb_filter_library.setChecked(False)
        self.cb_activate_live_tracking = self.cc.QCheckBox("Active Live PicHash Queries")
        self.cb_activate_live_tracking.setChecked(True)
        ### self.cb_filter_library.stateChanged.connect(self.populateBestMatchTable)
        # horizontal line
        self.hline = self.cc.QFrame()
        self.hline.setFrameShape(self.hline.HLine)
        self.hline.setFrameShadow(self.hline.Sunken)
        # upper table
        self.label_pichash_matches = self.cc.QLabel("PicHashMatches")
        self.table_pichash_matches = self.cc.QTableWidget()
        # lower table
        self.label_picblockhash_matches = self.cc.QLabel("PicBlockHashMatches")
        self.table_picblockhash_matches = self.cc.QTableWidget()
        ### self.table_picblockhash_matches.doubleClicked.connect(self._onTablePicBlockHashDoubleClicked)
        # static links to objects to help IDA
        self.NumberQTableWidgetItem = NumberQTableWidgetItem
        self._QtShim = QtShim
        self._createGui()

    def _createGui(self):
        """
        Setup function for the full GUI of this widget.
        """
        # layout and fill the widget
        sample_info_layout = self.cc.QVBoxLayout()
        sample_info_layout.addWidget(self.label_current_pichash_matches)
        sample_info_layout.addWidget(self.cb_filter_library)
        sample_info_layout.addWidget(self.cb_activate_live_tracking)
        sample_info_layout.addWidget(self.hline)
        sample_info_layout.addWidget(self.label_pichash_matches)
        sample_info_layout.addWidget(self.table_pichash_matches)
        sample_info_layout.addWidget(self.label_picblockhash_matches)
        sample_info_layout.addWidget(self.table_picblockhash_matches)
        self.central_widget.setLayout(sample_info_layout)

    def locate_cursor(self, view):
        """
        Courtesy of Alex Hanel's FunctionTrapperKeeper
        https://github.com/alexander-hanel/FunctionTrapperKeeper/blob/main/function_trapper_keeper.py
        """
        widgetType = idaapi.get_widget_type(view)
        if widgetType == idaapi.BWN_DISASM:
            ea = ida_kernwin.get_screen_ea()
            if not ea:
                return
            # validate offset is within a function
            temp_current_function = ida_funcs.get_func(ea)
            if not temp_current_function:
                return
            # get the start of the function
            temp_current_f = temp_current_function.start_ea
            if not temp_current_f:
                return
            if temp_current_f != self.parent.current_function:
                self.parent.current_function = temp_current_f

        elif widgetType == idaapi.BWN_PSEUDOCODE:
            ea = ida_kernwin.get_screen_ea()
            if not ea:
                return
            cfunc = idaapi.decompile(ea)
            for cc, item in enumerate(cfunc.treeitems):
                if item.ea != idaapi.BADADDR:
                    if cfunc.treeitems.at(cc).ea == ea:
                        # cursor offset was found in decompiler tree
                        # validate offset is within a function
                        cur_func = ida_funcs.get_func(ea)
                        if not cur_func:
                            return
                            # get the start of the function
                        current_f = cur_func.start_ea
                        if not current_f:
                            return
                        if current_f != self.parent.current_function:
                            self.parent.current_function = current_f
        return self.parent.current_function

    def hook_refresh(self, view):
        if self.parent.local_smda_report is None:
            self.label_current_pichash_matches.setText("Cannot check for matches, need to convert IDB to SMDA report first.")
            return
        if not self.cb_activate_live_tracking.isChecked():
            self.label_current_pichash_matches.setText("Live PicHash queries are deactivated.")
            return
        # get current function from cursor position
        current_function = self.locate_cursor(view)
        if current_function is None:
            return
        smda_function = self.parent.local_smda_report.getFunction(current_function)
        pic_hash = smda_function.getPicHashAsLong()
        # check if pichash match data is already available in local cache
        if pic_hash not in self.parent.pichash_matches:
            self.parent.mcrit_interface.queryPicHashMatches(pic_hash)
        pic_hash_match_summary = self.parent.pichash_match_summaries.get(pic_hash, None)
        if pic_hash_match_summary:
            self.label_current_pichash_matches.setText("PicHash Matches for Function: 0x%x -- %d families, %d samples, %d functions." % (current_function, pic_hash_match_summary["families"], pic_hash_match_summary["samples"], pic_hash_match_summary["functions"]))
        # populate tables with data
        # set scope in block table to currently selected block
