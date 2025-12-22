import idaapi
import ida_funcs
import ida_kernwin

from mcrit.storage.MatchingResult import MatchingResult
from mcrit.storage.MatchedFunctionEntry import MatchedFunctionEntry
from mcrit.matchers.FunctionCfgMatcher import FunctionCfgMatcher

import helpers.QtShim as QtShim
import helpers.McritTableColumn as McritTableColumn
QMainWindow = QtShim.get_QMainWindow()
from widgets.NumberQTableWidgetItem import NumberQTableWidgetItem
from widgets.SmdaGraphViewer import SmdaGraphViewer


class FunctionMatchWidget(QMainWindow):

    def __init__(self, parent):
        self.cc = parent.cc
        self.cc.QMainWindow.__init__(self)
        print("[|] loading FunctionMatchWidget")
        # enable access to shared MCRIT4IDA modules
        self.parent = parent
        self.last_viewed = None
        self.name = "Function Scope"
        self.last_family_selected = None
        self.icon = self.cc.QIcon(self.parent.config.ICON_FILE_PATH + "flag-triangle.png")
        self.central_widget = self.cc.QWidget()
        self.setCentralWidget(self.central_widget)
        self.current_function_offset = None
        self.label_current_function_matches = self.cc.QLabel("Matches for: <function_offset>")
        self.cb_filter_library = self.cc.QCheckBox("Filter out Library Matches")
        self.cb_filter_library.setEnabled(False)
        self.cb_filter_library.setChecked(self.parent.config.FUNCTION_FILTER_LIBRARY_FUNCTIONS)
        self.cb_filter_library.clicked.connect(self._onCbFilterLibraryClicked)
        self.cb_activate_live_tracking = self.cc.QCheckBox("Live Function Queries")
        self.cb_activate_live_tracking.setEnabled(False)
        self.cb_activate_live_tracking.setChecked(self.parent.config.FUNCTION_LIVE_QUERY)
        self.cb_activate_live_tracking.clicked.connect(self._onCbLiveClicked)
        # filter wheel
        self.sb_score_threshold = self.cc.QSpinBox()
        self.sb_score_threshold.setRange(50, 100)
        self.sb_score_threshold.setValue(self.parent.config.FUNCTION_MIN_SCORE)
        self.sb_score_threshold.valueChanged.connect(self.handleSpinThresholdChange)
        self.label_sb_threshold = self.cc.QLabel("Min. Score: ")
        self.b_query_single = self.cc.QPushButton("Query current function")
        self.b_query_single.clicked.connect(self.queryCurrentFunction)
        self.b_query_single.setEnabled(False)
        ### self.cb_filter_library.stateChanged.connect(self.populateBestMatchTable)
        # horizontal line
        self.hline = self.cc.QFrame()
        self.hline.setFrameShape(self.cc.QFrameHLine)
        self.hline.setFrameShadow(self.cc.QFrameShadow.Sunken)
        # upper table
        self.label_function_matches = self.cc.QLabel("Function Matches")
        self.table_function_matches = self.cc.QTableWidget()
        self.table_function_matches.doubleClicked.connect(self._onTableFunctionMatchDoubleClicked)
        self.table_function_matches.setContextMenuPolicy(self.cc.QtCore.Qt.CustomContextMenu)
        self.table_function_matches.customContextMenuRequested.connect(self._onTableFunctionMatchRightClicked)

        # lower table
        self.label_function_names = self.cc.QLabel("Names from Matched Functions")
        self.table_function_names = self.cc.QTableWidget()
        self.table_function_names.doubleClicked.connect(self._onTableFunctionNameDoubleClicked)
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
        self.controls_widget = self.cc.QWidget()
        controls_layout = self.cc.QHBoxLayout()
        # checkboxes
        self.checkbox_widget = self.cc.QWidget()
        checkbox_layout = self.cc.QVBoxLayout()
        checkbox_layout.addWidget(self.cb_filter_library)
        checkbox_layout.addWidget(self.cb_activate_live_tracking)
        self.checkbox_widget.setLayout(checkbox_layout)
        # threshold spinbox and label
        self.threshold_widget = self.cc.QWidget()
        threshold_layout = self.cc.QVBoxLayout()
        threshold_layout.addWidget(self.label_sb_threshold)
        threshold_layout.addWidget(self.sb_score_threshold)
        self.threshold_widget.setLayout(threshold_layout)
        # glue controls
        controls_layout.addWidget(self.checkbox_widget)
        controls_layout.addWidget(self.threshold_widget)
        self.controls_widget.setLayout(controls_layout)
        # glue all together
        sample_info_layout.addWidget(self.label_current_function_matches)
        sample_info_layout.addWidget(self.controls_widget)
        sample_info_layout.addWidget(self.b_query_single)
        sample_info_layout.addWidget(self.hline)
        sample_info_layout.addWidget(self.label_function_matches)
        sample_info_layout.addWidget(self.table_function_matches)
        sample_info_layout.addWidget(self.label_function_names)
        sample_info_layout.addWidget(self.table_function_names)
        self.central_widget.setLayout(sample_info_layout)

    def _onCbFilterLibraryClicked(self, mi):
        """
        If the filter is altered, we refresh the table.
        """
        self.hook_refresh(None, use_current_function=True)

    def _onCbLiveClicked(self, mi):
        if self.cb_activate_live_tracking.isChecked():
            self.parent.main_widget.hideLocalWidget()
            self.updateViewWithCurrentFunction()

    def handleSpinThresholdChange(self):
        self.updateViewWithCurrentFunction()

    def enable(self):
        self.cb_filter_library.setEnabled(True)
        self.cb_activate_live_tracking.setEnabled(True)
        self.b_query_single.setEnabled(True)

    def updateCurrentFunction(self, view):
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

    def queryCurrentFunction(self):
        self.parent.main_widget.hideLocalWidget()
        self.updateViewWithCurrentFunction()

    def hook_refresh(self, view, use_current_function=False):
        if self.parent.local_smda_report is None:
            self.label_current_function_matches.setText("Cannot check for matches, need to convert IDB to SMDA report first.")
            return
        # get current function from cursor position
        if self.updateCurrentFunction(view) is None and not use_current_function:
            return
        if self.parent.current_function == self.last_viewed and not use_current_function:
            return
        if not self.cb_activate_live_tracking.isChecked():
            self.clearTable()
            self.label_current_function_matches.setText("Live Function Queries are deactivated.")
            return
        self.updateViewWithCurrentFunction()
        
    def clearTable(self):
        # upper table
        self.table_function_matches.clear()
        self.table_function_matches.setSortingEnabled(False)
        self.function_matches_header_labels = [McritTableColumn.MAP_COLUMN_TO_HEADER_STRING[col] for col in self.parent.config.FUNCTION_MATCHES_TABLE_COLUMNS]
        self.table_function_matches.setColumnCount(len(self.function_matches_header_labels))
        self.table_function_matches.setHorizontalHeaderLabels(self.function_matches_header_labels)
        self.table_function_matches.setRowCount(0)
        self.table_function_matches.resizeRowToContents(0)
        # lower table
        self.table_function_names.clear()
        self.table_function_names.setSortingEnabled(False)
        self.function_names_header_labels = [McritTableColumn.MAP_COLUMN_TO_HEADER_STRING[col] for col in self.parent.config.FUNCTION_NAMES_TABLE_COLUMNS]
        self.table_function_names.setColumnCount(len(self.function_names_header_labels))
        self.table_function_names.setHorizontalHeaderLabels(self.function_names_header_labels)
        self.table_function_names.setRowCount(0)
        self.table_function_names.resizeRowToContents(0)

    def updateViewWithCurrentFunction(self):
        self.last_viewed = self.parent.current_function
        smda_function = self.parent.local_smda_report.getFunction(self.parent.current_function)
        if smda_function is None or smda_function.num_instructions < 10:
            self.clearTable()
            self.label_current_function_matches.setText("Can only query functions with 10 instructions or more.")
            return
        single_function_smda_report = self.parent.getLocalSmdaReportOutline()
        single_function_smda_report.xcfg = {smda_function.offset: smda_function}
        # check if pichash match data is already available in local cache
        if smda_function.offset not in self.parent.function_matches:
            self.parent.mcrit_interface.querySmdaFunctionMatches(single_function_smda_report)
        if smda_function.offset in self.parent.function_matches:
            match_report = MatchingResult.fromDict(self.parent.function_matches[smda_function.offset])
            match_report.filterToFunctionScore(int(self.sb_score_threshold.value()))
            num_all_functions = len(match_report.function_matches)
            if self.cb_filter_library.isChecked():
                num_functions = len([m for m in match_report.filtered_function_matches if not m.match_is_library])
                self.label_current_function_matches.setText("Matches for Function: 0x%x -- %d families, %d samples, %d functions (%d filtered)." % (self.parent.current_function, match_report.num_original_family_matches, match_report.num_original_sample_matches, num_functions, num_all_functions - num_functions))
            elif len(match_report.filtered_function_matches) < len(match_report.function_matches):
                self.label_current_function_matches.setText("Matches for Function: 0x%x -- %d families, %d samples, %d functions (%d filtered)." % (self.parent.current_function, match_report.num_original_family_matches, match_report.num_original_sample_matches, len(match_report.filtered_function_matches), num_all_functions - len(match_report.filtered_function_matches)))
                self.current_function_offset = self.parent.current_function
            else:
                self.label_current_function_matches.setText("Matches for Function: 0x%x -- %d families, %d samples, %d functions." % (self.parent.current_function, match_report.num_original_family_matches, match_report.num_original_sample_matches, num_all_functions))
                self.current_function_offset = self.parent.current_function
        if match_report:
            # populate tables with data
            self.populateFunctionMatchTable(match_report)
            # TODO fetch all labels to populate lower table as soon as we support this 
            self.populateFunctionNameTable(match_report)

    def generateMatchTableCellItem(self, column_type, function_match_entry: MatchedFunctionEntry):
        tmp_item = None
        if column_type == McritTableColumn.FUNCTION_ID:
            tmp_item = self.NumberQTableWidgetItem("%d" % function_match_entry.matched_function_id)
        elif column_type == McritTableColumn.SHA256:
            sample_sha256 = self.parent.sample_infos[function_match_entry.matched_sample_id].sha256
            tmp_item = self.cc.QTableWidgetItem(sample_sha256[:8])
        elif column_type == McritTableColumn.SAMPLE_ID:
            tmp_item = self.NumberQTableWidgetItem("%d" % function_match_entry.matched_sample_id)
        elif column_type == McritTableColumn.FAMILY_NAME:
            family_name = self.parent.family_infos[function_match_entry.matched_family_id].family_name
            tmp_item = self.cc.QTableWidgetItem(family_name)
        elif column_type == McritTableColumn.VERSION:
            sample_version = self.parent.sample_infos[function_match_entry.matched_sample_id].version
            tmp_item = self.cc.QTableWidgetItem(sample_version)
        elif column_type == McritTableColumn.PIC_HASH_MATCH:
            tmp_item = self.cc.QTableWidgetItem("YES" if function_match_entry.match_is_pichash else "NO")
        elif column_type == McritTableColumn.SCORE:
            tmp_item = self.NumberQTableWidgetItem("%d" % function_match_entry.matched_score)
        elif column_type == McritTableColumn.IS_LIBRARY:
            library_value = "YES" if function_match_entry.match_is_library else "NO"
            tmp_item = self.cc.QTableWidgetItem("%s" % library_value)
        return tmp_item

    def populateFunctionMatchTable(self, match_report: MatchingResult):
        """
        Populate the function match table with all matches for the selected function_id
        """
        self.table_function_matches.setSortingEnabled(False)
        self.function_matches_header_labels = [McritTableColumn.MAP_COLUMN_TO_HEADER_STRING[col] for col in self.parent.config.FUNCTION_MATCHES_TABLE_COLUMNS]
        self.table_function_matches.clear()
        self.table_function_matches.setColumnCount(len(self.function_matches_header_labels))
        self.table_function_matches.setHorizontalHeaderLabels(self.function_matches_header_labels)
        # Identify number of table entries and prepare addresses to display
        if self.cb_filter_library.isChecked():
            self.table_function_matches.setRowCount(len([m for m in match_report.filtered_function_matches if not m.match_is_library]))
        else:
            self.table_function_matches.setRowCount(len(match_report.filtered_function_matches))
        self.table_function_matches.resizeRowToContents(0)

        row = 0
        sorted_entries = sorted(match_report.filtered_function_matches, key=lambda x: x.matched_score + (1 if x.match_is_pichash else 0)+ (1 if x.match_is_library else 0), reverse=True)
        for function_match_entry in sorted_entries:
            if self.cb_filter_library.isChecked() and function_match_entry.match_is_library:
                continue
            for column, column_name in enumerate(self.function_matches_header_labels):
                column_type = self.parent.config.FUNCTION_MATCHES_TABLE_COLUMNS[column]
                tmp_item = self.generateMatchTableCellItem(column_type, function_match_entry)
                tmp_item.setFlags(tmp_item.flags() & ~self.cc.QtCore.Qt.ItemIsEditable)
                self.table_function_matches.setItem(row, column, tmp_item)
            # self.table_function_matches.resizeRowToContents(row)
            row += 1
        self.table_function_matches.setSelectionMode(self.cc.QAbstractItemView.SingleSelection)
        self.table_function_matches.resizeColumnsToContents()
        self.table_function_matches.setSortingEnabled(True)
        header_view = self._QtShim.get_QHeaderView()
        header = self.table_function_matches.horizontalHeader()
        header.setStretchLastSection(True)

    def generateNameTableCellItem(self, column_type, function_label_entry):
        tmp_item = None
        if column_type == McritTableColumn.FUNCTION_ID:
            tmp_item = self.NumberQTableWidgetItem("%d" % function_label_entry.function_id)
        elif column_type == McritTableColumn.SCORE:
            tmp_item = self.NumberQTableWidgetItem("%d" % function_label_entry.score)
        elif column_type == McritTableColumn.USER:
            tmp_item = self.cc.QTableWidgetItem(function_label_entry.username)
        elif column_type == McritTableColumn.FUNCTION_LABEL:
            tmp_item = self.cc.QTableWidgetItem(function_label_entry.function_label)
        elif column_type == McritTableColumn.TIMESTAMP:
            timestamp = function_label_entry.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            tmp_item = self.cc.QTableWidgetItem(timestamp)
        return tmp_item

    def populateFunctionNameTable(self, match_report: MatchingResult):
        """
        Populate the function name table with all names for the matches we found
        """
        function_matches_by_id = {match.matched_function_id: match for match in match_report.filtered_function_matches}
        self.parent.mcrit_interface.queryFunctionEntriesById([i for i in function_matches_by_id.keys()])
        matched_entries = {}
        for function_id in function_matches_by_id.keys():
            matched_entries[function_id] = self.parent.matched_function_entries[function_id]
        function_label_entries = []
        for function_id, entry in matched_entries.items():
            if self.cb_filter_library.isChecked() and function_matches_by_id[entry.function_id].match_is_library:
                continue
            if entry.function_labels:
                for function_label in entry.function_labels:
                    function_label.score = function_matches_by_id[function_id].matched_score
                    function_label_entries.append(function_label)

        self.table_function_names.setSortingEnabled(False)
        self.function_matches_header_labels = [McritTableColumn.MAP_COLUMN_TO_HEADER_STRING[col] for col in self.parent.config.FUNCTION_NAMES_TABLE_COLUMNS]
        self.table_function_names.clear()
        self.table_function_names.setColumnCount(len(self.function_matches_header_labels))
        self.table_function_names.setHorizontalHeaderLabels(self.function_matches_header_labels)
        # Identify number of table entries and prepare addresses to display
        self.table_function_names.setRowCount(len(function_label_entries))
        self.table_function_names.resizeRowToContents(0)

        row = 0
        sorted_entries = sorted(function_label_entries, key=lambda x: (x.score, x.username, x.timestamp), reverse=True)
        for function_label_entry in sorted_entries:
            for column, column_name in enumerate(self.function_matches_header_labels):
                column_type = self.parent.config.FUNCTION_NAMES_TABLE_COLUMNS[column]
                tmp_item = self.generateNameTableCellItem(column_type, function_label_entry)
                tmp_item.setFlags(tmp_item.flags() & ~self.cc.QtCore.Qt.ItemIsEditable)
                self.table_function_names.setItem(row, column, tmp_item)
            # self.table_function_matches.resizeRowToContents(row)
            row += 1
        self.table_function_names.setSelectionMode(self.cc.QAbstractItemView.SingleSelection)
        self.table_function_names.resizeColumnsToContents()
        self.table_function_names.setSortingEnabled(True)
        header_view = self._QtShim.get_QHeaderView()
        header = self.table_function_names.horizontalHeader()
        header.setStretchLastSection(True)


    def _onTableFunctionMatchDoubleClicked(self, mi):
        """
        Use the row with that was double clicked to import the function_name to the current function
        """
        function_id_column_index = McritTableColumn.columnTypeToIndex(McritTableColumn.FUNCTION_ID, self.parent.config.FUNCTION_MATCHES_TABLE_COLUMNS)
        if function_id_column_index is not None:
            remote_function_id = int(self.table_function_matches.item(mi.row(), function_id_column_index).text())
            smda_function_a = self.parent.local_smda_report.getFunction(self.current_function_offset)
            smda_report_a = self.parent.local_smda_report
            function_entry_b = self.parent.mcrit_interface.queryFunctionEntryById(remote_function_id)
            smda_function_b = function_entry_b.toSmdaFunction()
            sample_entry_b = self.parent.mcrit_interface.querySampleEntryById(function_entry_b.sample_id)
            fcm = FunctionCfgMatcher(smda_report_a, smda_function_a, sample_entry_b, smda_function_b)
            coloring = fcm.getColoredMatches()
            coloring = {int(k[6:], 16): int(v[1:], 16) for k, v in coloring["b"].items()}
            g = SmdaGraphViewer(self, sample_entry_b, function_entry_b, smda_function_b, coloring)
            g.Show()

    def _onTableFunctionNameDoubleClicked(self, mi):
        """
        Use the row with that was double clicked to import the function_name to the current function
        """
        function_id_column_index = McritTableColumn.columnTypeToIndex(McritTableColumn.FUNCTION_ID, self.parent.config.FUNCTION_NAMES_TABLE_COLUMNS)
        function_label_column_index = McritTableColumn.columnTypeToIndex(McritTableColumn.FUNCTION_LABEL, self.parent.config.FUNCTION_NAMES_TABLE_COLUMNS)
        if function_id_column_index is not None and mi.column() == function_id_column_index:
            smda_function_a = self.parent.local_smda_report.getFunction(self.current_function_offset)
            smda_report_a = self.parent.local_smda_report
            remote_function_id = int(self.table_function_names.item(mi.row(), function_id_column_index).text())
            function_entry_b = self.parent.mcrit_interface.queryFunctionEntryById(remote_function_id)
            smda_function_b = function_entry_b.toSmdaFunction()
            sample_entry_b = self.parent.mcrit_interface.querySampleEntryById(function_entry_b.sample_id)
            fcm = FunctionCfgMatcher(smda_report_a, smda_function_a, sample_entry_b, smda_function_b)
            coloring = fcm.getColoredMatches()
            coloring = {int(k[6:], 16): int(v[1:], 16) for k, v in coloring["b"].items()}
            g = SmdaGraphViewer(self, sample_entry_b, function_entry_b, smda_function_b, coloring)
            g.Show()
        elif function_label_column_index is not None and mi.column() == function_label_column_index:
            function_name = self.table_function_names.item(mi.row(), function_label_column_index).text()
            # print(function_name)
            self.cc.ida_proxy.set_name(self.last_viewed, function_name, self.cc.ida_proxy.SN_NOWARN)

    def _onTableFunctionMatchRightClicked(self, position):
        """
        Right click context menu for function matches
        """
        sha256_column_index = McritTableColumn.columnTypeToIndex(McritTableColumn.SHA256, self.parent.config.FUNCTION_MATCHES_TABLE_COLUMNS)
        sample_id_column_index = McritTableColumn.columnTypeToIndex(McritTableColumn.SAMPLE_ID, self.parent.config.FUNCTION_MATCHES_TABLE_COLUMNS)
        if sha256_column_index is not None and self.table_function_matches.currentColumn() == sha256_column_index:
            if sample_id_column_index is None:
                # TODO possibly can reconstruct clicked row from matching data, but let's keep it simple for now
                print("Need a column with sample IDs to copy SHA256 to clipboard.")
            # copy to clipboard
            sample_id = self.table_function_matches.item(self.table_function_matches.currentRow(), sample_id_column_index).text()
            sha256 = self.parent.sample_infos[int(sample_id)].sha256
            self.parent.copyStringToClipboard(sha256)
