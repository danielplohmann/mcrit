import idaapi
import ida_funcs
import ida_kernwin

from mcrit.storage.MatchingResult import MatchingResult
from mcrit.matchers.FunctionCfgMatcher import FunctionCfgMatcher

import helpers.QtShim as QtShim
QMainWindow = QtShim.get_QMainWindow()
from widgets.NumberQTableWidgetItem import NumberQTableWidgetItem
from widgets.SmdaGraphViewer import SmdaGraphViewer


class BlockMatchWidget(QMainWindow):

    def __init__(self, parent):
        self.cc = parent.cc
        self.cc.QMainWindow.__init__(self)
        print("[|] loading BlockMatchWidget")
        # enable access to shared MCRIT4IDA modules
        self.parent = parent
        self.last_viewed_function = None
        self.last_viewed_block = None
        self._last_block_matches = None
        self.name = "Block Scope"
        self.last_family_selected = None
        self.icon = self.cc.QIcon(self.parent.config.ICON_FILE_PATH + "puzzle.png")
        self.central_widget = self.cc.QWidget()
        self.setCentralWidget(self.central_widget)
        self.label_current_function_matches = self.cc.QLabel("Block Matches for: <function_offset>")
        self.cb_filter_library = self.cc.QCheckBox("Filter out Library Matches")
        self.cb_filter_library.setEnabled(False)
        self.cb_filter_library.setChecked(False)
        self.cb_filter_library.clicked.connect(self._onCbFilterLibraryClicked)
        self.cb_activate_live_tracking = self.cc.QCheckBox("Live Block Queries")
        self.cb_activate_live_tracking.setEnabled(False)
        self.cb_activate_live_tracking.setChecked(False)
        self.b_query_single = self.cc.QPushButton("Query current basic block")
        self.b_query_single.clicked.connect(self.queryCurrentBlock)
        self.b_query_single.setEnabled(False)
        ### self.cb_filter_library.stateChanged.connect(self.populateBestMatchTable)
        # horizontal line
        self.hline = self.cc.QFrame()
        self.hline.setFrameShape(self.hline.HLine)
        self.hline.setFrameShadow(self.hline.Sunken)
        # upper table
        self.label_block_summary = self.cc.QLabel("Blocks Summary")
        self.table_block_summary = self.cc.QTableWidget()
        self.table_block_summary.clicked.connect(self._onTableBlockSummaryClicked)
        self.table_block_summary.doubleClicked.connect(self._onTableBlockSummaryDoubleClicked)
        # lower table
        self.label_block_matches = self.cc.QLabel("Block Matches for <block_offset>")
        self.table_block_matches = self.cc.QTableWidget()
        self.table_block_matches.doubleClicked.connect(self._onTableBlockMatchesDoubleClicked)
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
        sample_info_layout.addWidget(self.label_current_function_matches)
        sample_info_layout.addWidget(self.cb_filter_library)
        sample_info_layout.addWidget(self.cb_activate_live_tracking)
        sample_info_layout.addWidget(self.b_query_single)
        sample_info_layout.addWidget(self.hline)
        sample_info_layout.addWidget(self.label_block_summary)
        sample_info_layout.addWidget(self.table_block_summary)
        sample_info_layout.addWidget(self.label_block_matches)
        sample_info_layout.addWidget(self.table_block_matches)
        self.central_widget.setLayout(sample_info_layout)

    def _onCbFilterLibraryClicked(self, mi):
        """
        If the filter is altered, we refresh the table.
        """
        self.hook_refresh(None, use_current_block=True)

    def enable(self):
        self.cb_filter_library.setEnabled(True)
        self.cb_activate_live_tracking.setEnabled(True)
        self.b_query_single.setEnabled(True)

    def updateCurrentBlock(self, view):
        """
        Courtesy of Alex Hanel's FunctionTrapperKeeper
        https://github.com/alexander-hanel/FunctionTrapperKeeper/blob/main/function_trapper_keeper.py
        """
        if view is None:
            return
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
            temp_current_block = self.parent.local_smda_report.findBlockByContainedAddress(ea)
            if temp_current_block and temp_current_block.offset != self.parent.current_block:
                self.parent.current_block = temp_current_block.offset

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
                        temp_current_block = self.parent.local_smda_report.findBlockByContainedAddress(ea)
                        if temp_current_block and temp_current_block.offset != self.parent.current_block:
                            self.parent.current_block = temp_current_block.offset
        return self.parent.current_function

    def queryCurrentBlock(self):
        self.updateViewWithCurrentBlock()

    def hook_refresh(self, view, use_current_block=False):
        if self.parent.local_smda_report is None:
            self.label_current_function_matches.setText("Cannot check for matches, need to convert IDB to SMDA report first.")
            return
        # get current function from cursor position
        if self.updateCurrentBlock(view) is None and not use_current_block:
            return
        if self.parent.current_function == self.last_viewed_function and not use_current_block:
            return
        if not self.cb_activate_live_tracking.isChecked():
            self.clearTable()
            self.label_current_function_matches.setText("Live Function Queries are deactivated.")
            return
        self.updateViewWithCurrentBlock()
        
    def clearTable(self):
        # upper table
        self.table_block_summary.clear()
        self.table_block_summary.setSortingEnabled(False)
        self.function_matches_header_labels = ["Offset", "PicBlockHash", "Length", "Families", "Samples", "Functions", "Lib"]
        self.table_block_summary.setColumnCount(len(self.function_matches_header_labels))
        self.table_block_summary.setHorizontalHeaderLabels(self.function_matches_header_labels)
        self.table_block_summary.setRowCount(0)
        self.table_block_summary.resizeRowToContents(0)
        # lower table
        self.table_block_matches.clear()
        self.table_block_matches.setSortingEnabled(False)
        self.function_matches_header_labels = ["Family", "Sample", "Function", "Offset"]
        self.table_block_matches.setColumnCount(len(self.function_matches_header_labels))
        self.table_block_matches.setHorizontalHeaderLabels(self.function_matches_header_labels)
        self.table_block_matches.setRowCount(0)
        self.table_block_matches.resizeRowToContents(0)

    def updateViewWithCurrentBlock(self):
        if self.parent.family_infos is None:
            self.parent.mcrit_interface.queryAllFamilyEntries()
        self.last_viewed_function = self.parent.current_function
        self.last_viewed_block = self.parent.current_block
        if self.parent.current_block:
            self.label_block_matches.setText("No Block Matches for: 0x%x" % self.parent.current_block)
        smda_function = self.parent.local_smda_report.getFunction(self.parent.current_function)
        if smda_function is None or smda_function.num_instructions < 4:
            self.clearTable()
            self.label_current_function_matches.setText("Can only query functions with 4 instructions or more.")
            return
        # calculate all block pichashes
        pbh = FunctionCfgMatcher.getPicBlockHashesForFunction(self.parent.local_smda_report, smda_function)
        block_matches_by_offset = {}
        for entry in pbh:
            if entry["size"] >= 4:
                # cache this so we only query once per block
                if entry["offset"] not in self.parent.block_matches:
                    pichash_matches = self.parent.mcrit_interface.getMatchesForPicBlockHash(entry["hash"])
                    self.parent.block_matches[entry["offset"]] = pichash_matches
                pichash_matches = self.parent.block_matches[entry["offset"]]
                summary = {
                    "families": len(set([e[0] for e in pichash_matches])),
                    "samples": len(set([e[1] for e in pichash_matches])),
                    "functions": len(set([e[2] for e in pichash_matches])),
                    "offsets" : len(pichash_matches)
                }
                block_matches_by_offset[entry["offset"]] = {
                    "picblockhash": entry,
                    "matches": self.parent.block_matches[entry["offset"]],
                    "summary": summary,
                    "has_library_matches": False
                }

        if block_matches_by_offset:
            # TODO when filtering, we should actually fully remove them by offset here, as we don't want to see such blocks in the summary later on
            set_families = set([])
            set_samples = set([])
            set_all_functions = set([])
            set_functions = set([])
            library_families = []
            for k, v in self.parent.family_infos.items():
                if v.num_samples and v.num_library_samples == v.num_samples:
                    library_families.append(k)
            offsets_to_drop = []
            for offset, data in block_matches_by_offset.items():
                set_all_functions.update([entry[2] for entry in data["matches"]])
                filtered_matches = [entry for entry in data["matches"] if entry[0] not in library_families]
                if len(filtered_matches) < len(data["matches"]):
                    block_matches_by_offset[offset]["has_library_matches"] = True
                    offsets_to_drop.append(offset)
                # reduce matches if we actually have matched some blocks against libraries
                if self.cb_filter_library.isChecked() and block_matches_by_offset[offset]["has_library_matches"]:
                    block_matches_by_offset[offset]["matches"] = filtered_matches
                    continue
                block_matches_by_offset[offset]["summary"] = {
                    "families": len(set([e[0] for e in filtered_matches])),
                    "samples": len(set([e[1] for e in filtered_matches])),
                    "functions": len(set([e[2] for e in filtered_matches])),
                    "offsets" : len(filtered_matches)
                }
                set_families.update([entry[0] for entry in filtered_matches])
                set_samples.update([entry[1] for entry in filtered_matches])
                set_functions.update([entry[2] for entry in filtered_matches])
            if self.cb_filter_library.isChecked():
                for offset in offsets_to_drop:
                    block_matches_by_offset.pop(offset)
                self.label_current_function_matches.setText("Block Matches for Function: 0x%x -- %d families, %d samples, %d functions (%d filtered)." % (self.parent.current_function, len(set_families), len(set_samples), len(set_functions), len(set_all_functions) - len(set_functions)))
            else:
                self.label_current_function_matches.setText("Block Matches for Function: 0x%x -- %d families, %d samples, %d functions." % (self.parent.current_function, len(set_families), len(set_samples), len(set_all_functions)))
                self.current_block_offset = self.parent.current_function
        else:
            self.label_current_function_matches.setText("No Block Matches for Function: 0x%x" % self.parent.current_function)
            self.label_block_matches.setText("No Block Matches for: 0x%x" % self.parent.current_block)
        self._last_block_matches = block_matches_by_offset
        # populate tables with data
        self.populateBlockSummaryTable(block_matches_by_offset)
        # TODO pre-select the row for our current block
        self.populateBlockMatchTable(block_matches_by_offset, self.last_viewed_block)

    def populateBlockSummaryTable(self, block_matches):
        """
        Populate the function match table with all matches for the selected function_id
        """
        self.table_block_summary.setSortingEnabled(False)
        self.function_matches_header_labels = ["Offset", "PicBlockHash", "Length", "Families", "Samples", "Functions", "Lib"]
        self.table_block_summary.clear()
        self.table_block_summary.setColumnCount(len(self.function_matches_header_labels))
        self.table_block_summary.setHorizontalHeaderLabels(self.function_matches_header_labels)
        # Identify number of table entries and prepare addresses to display
        self.table_block_summary.setRowCount(len(block_matches))
        self.table_block_summary.resizeRowToContents(0)
        row = 0
        for block_offset, block_entry in sorted(block_matches.items(), key=lambda x: x[0]):
            has_library_sample_block = False
            for column, column_name in enumerate(self.function_matches_header_labels):
                tmp_item = None
                if column == 0:
                    tmp_item = self.cc.QTableWidgetItem("0x%x" % block_offset)
                elif column == 1:
                    tmp_item = self.cc.QTableWidgetItem("0x%x" % block_entry["picblockhash"]["hash"])
                elif column == 2:
                    tmp_item = self.NumberQTableWidgetItem("%d" % block_entry["picblockhash"]["size"])
                elif column == 3:
                    tmp_item = self.NumberQTableWidgetItem("%d" % block_entry["summary"]["families"])
                elif column == 4:
                    tmp_item = self.NumberQTableWidgetItem("%d" % block_entry["summary"]["samples"])
                elif column == 5:
                    tmp_item = self.NumberQTableWidgetItem("%d" % block_entry["summary"]["functions"])
                elif column == 6:
                    tmp_item = self.cc.QTableWidgetItem("YES" if block_entry["has_library_matches"] else "NO")
                tmp_item.setFlags(tmp_item.flags() & ~self.cc.QtCore.Qt.ItemIsEditable)
                self.table_block_summary.setItem(row, column, tmp_item)
            # self.table_function_matches.resizeRowToContents(row)
            row += 1
        self.table_block_summary.setSelectionMode(self.cc.QAbstractItemView.SingleSelection)
        self.table_block_summary.resizeColumnsToContents()
        self.table_block_summary.setSortingEnabled(True)
        header_view = self._QtShim.get_QHeaderView()
        header = self.table_block_summary.horizontalHeader()
        header.setStretchLastSection(True)

    def populateBlockMatchTable(self, block_matches, block_offset):
        """
        Populate the function name table with all names for the matches we found
        """
        self.label_block_matches.setText("Block Matches for: 0x%x" % self.parent.current_block)
        self.table_block_matches.setSortingEnabled(False)
        self.function_matches_header_labels = ["Family", "Family ID", "Sample ID", "Function ID", "Offset"]
        self.table_block_matches.clear()
        self.table_block_matches.setColumnCount(len(self.function_matches_header_labels))
        self.table_block_matches.setHorizontalHeaderLabels(self.function_matches_header_labels)
        # Identify number of table entries and prepare addresses to display
        if block_offset not in block_matches:
            self.table_block_matches.setRowCount(0)
            return
        self.table_block_matches.setRowCount(len(block_matches[block_offset]["matches"]))
        self.table_block_matches.resizeRowToContents(0)

        row = 0
        for match_entry in sorted(block_matches[block_offset]["matches"], key=lambda x: (x[0], x[1], x[2])):
            for column, column_name in enumerate(self.function_matches_header_labels):
                tmp_item = None
                if column == 0:
                    tmp_item = self.NumberQTableWidgetItem(self.parent.family_infos[match_entry[0]].family_name)
                elif column == 1:
                    tmp_item = self.NumberQTableWidgetItem("%d" % match_entry[0])
                elif column == 2:
                    tmp_item = self.NumberQTableWidgetItem("%d" % match_entry[1])
                elif column == 3:
                    tmp_item = self.NumberQTableWidgetItem("%d" % match_entry[2])
                elif column == 4:
                    tmp_item = self.cc.QTableWidgetItem("0x%x" % match_entry[3])
                tmp_item.setFlags(tmp_item.flags() & ~self.cc.QtCore.Qt.ItemIsEditable)
                self.table_block_matches.setItem(row, column, tmp_item)
            # self.table_function_matches.resizeRowToContents(row)
            row += 1
        self.table_block_matches.setSelectionMode(self.cc.QAbstractItemView.SingleSelection)
        self.table_block_matches.resizeColumnsToContents()
        self.table_block_matches.setSortingEnabled(True)
        header_view = self._QtShim.get_QHeaderView()
        header = self.table_block_matches.horizontalHeader()
        header.setStretchLastSection(True)

    def _onTableBlockSummaryClicked(self, mi):
        """
        Use the row with that was double clicked to import the function_name to the current function
        """
        clicked_block_address = self.table_block_summary.item(mi.row(), 0).text()
        # print("clicked_block_address", clicked_block_address)
        self.parent.current_block = int(clicked_block_address, 16)
        self.populateBlockMatchTable(self._last_block_matches, self.parent.current_block)

    def _onTableBlockSummaryDoubleClicked(self, mi):
        """
        Use the row with that was double clicked to import the function_name to the current function
        """
        if mi.column() == 0:
            clicked_block_address = self.table_block_summary.item(mi.row(), 0).text()
            # print("double clicked_block_address", clicked_block_address)
            self.cc.ida_proxy.Jump(int(clicked_block_address, 16))
            self.parent.current_block = int(clicked_block_address, 16)
            self.populateBlockMatchTable(self._last_block_matches, self.parent.current_block)

    def _onTableBlockMatchesDoubleClicked(self, mi):
        """
        Use the row with that was double clicked to import the function_name to the current function
        """
        block_offset_b = int(self.table_block_matches.item(mi.row(), 4).text(), 16)
        function_id_b = int(self.table_block_matches.item(mi.row(), 3).text())
        # print("double clicked row for function_id", function_id_b)
        function_entry_b = self.parent.mcrit_interface.queryFunctionEntryById(function_id_b)
        smda_function_b = function_entry_b.toSmdaFunction()
        sample_entry_b = self.parent.mcrit_interface.querySampleEntryById(function_entry_b.sample_id)
        coloring = {block_offset_b: 0xFFDD00}
        g = SmdaGraphViewer(self, sample_entry_b, function_entry_b, smda_function_b, coloring)
        g.Show()

