import re
import ida_funcs

import helpers.QtShim as QtShim
from widgets.NumberQTableWidgetItem import NumberQTableWidgetItem

QMainWindow = QtShim.get_QMainWindow()
QStyledItemDelegate = QtShim.get_QStyledItemDelegate()
QComboBox = QtShim.get_QComboBox()


class DropdownDelegate(QStyledItemDelegate):
    def __init__(self, function_name_mapping):
        super().__init__()
        self.function_name_mapping = function_name_mapping

    def createEditor(self, parent, option, index):
        editor = QComboBox(parent)
        choices = self.function_name_mapping.get((index.row(), index.column()), [])
        editor.addItems(choices)
        return editor

    def setEditorData(self, editor, index):
        value = index.data()
        editor.setCurrentText(value)

    def setModelData(self, editor, model, index):
        value = editor.currentText()
        model.setData(index, value)



class FunctionOverviewWidget(QMainWindow):

    def __init__(self, parent):
        self.cc = parent.cc
        self.cc.QMainWindow.__init__(self)
        print("[|] loading FunctionOverviewWidget")
        # enable access to shared MCRIT4IDA modules
        self.parent = parent
        self.name = "Function Overview"
        self.icon = self.cc.QIcon(self.parent.config.ICON_FILE_PATH + "relationship.png")
        self.central_widget = self.cc.QWidget()
        self.setCentralWidget(self.central_widget)
        self.b_fetch_labels = self.cc.QPushButton("Fetch labels for matches")
        self.b_fetch_labels.clicked.connect(self.fetchLabels)
        self.cb_labels_only = self.cc.QCheckBox("Filter to Functions with Labels only")
        self.cb_labels_only.setChecked(False)
        self.cb_labels_only.stateChanged.connect(self.populateFunctionTable)
        self.b_import_labels = self.cc.QPushButton("Import all labels for unnamed functions")
        # TODO implement an actual import function here
        self.b_import_labels.clicked.connect(self.importSelectedLabels)
        self.sb_minhash_threshold = self.cc.QSpinBox()
        self.sb_minhash_threshold.setRange(100, 100)
        self.sb_minhash_threshold.valueChanged.connect(self.handleSpinThresholdChange)
        self.global_minimum_match_value = None
        self.global_maximum_match_value = None
        # horizontal line
        self.hline = self.cc.QFrame()
        self.hline.setFrameShape(self.hline.HLine)
        self.hline.setFrameShadow(self.hline.Sunken)
        # table
        self.label_local_functions = self.cc.QLabel("Functions Matched")
        self.table_local_functions = self.cc.QTableWidget()
        self.table_local_functions.selectionModel().selectionChanged.connect(self._onTableFunctionsSelectionChanged)
        self.table_local_functions.clicked.connect(self._onTableFunctionsClicked)
        self.table_local_functions.doubleClicked.connect(self._onTableFunctionsDoubleClicked)
        # cache for function_names
        self.function_name_mapping = None
        # static links to objects to help IDA
        self.NumberQTableWidgetItem = NumberQTableWidgetItem
        self._QtShim = QtShim
        self._createGui()

    def _createGui(self):
        """
        Setup function for the full GUI of this widget.
        """
        # layout and fill the widget
        function_info_layout = self.cc.QVBoxLayout()
        function_info_layout.addWidget(self.b_fetch_labels)
        function_info_layout.addWidget(self.cb_labels_only)
        function_info_layout.addWidget(self.b_import_labels)
        function_info_layout.addWidget(self.sb_minhash_threshold)
        function_info_layout.addWidget(self.hline)
        function_info_layout.addWidget(self.label_local_functions)
        function_info_layout.addWidget(self.table_local_functions)
        self.central_widget.setLayout(function_info_layout)

################################################################################
# Rendering and state keeping
################################################################################

    def fetchLabels(self):
        match_report = self.parent.getMatchingReport()
        if match_report is None:
            return
        matched_function_ids = set()
        for function_match in match_report.function_matches:
            matched_function_ids.add(function_match.matched_function_id)
        print("Number of matched remote functions: ", len(matched_function_ids))
        self.parent.mcrit_interface.queryFunctionEntriesById(list(matched_function_ids), with_label_only=True)
        function_entries_with_labels = {}
        if self.parent.matched_function_entries:
            for function_id, function_entry in self.parent.matched_function_entries.items():
                if function_entry.function_labels:
                    function_entries_with_labels[function_id] = function_entry
        function_labels = []
        for function_id, entry in function_entries_with_labels.items():
            for label in entry.function_labels:
                print(label)
                function_labels.append(label)
        print("fetched function entries, found labels:", len(function_labels))
        self.update()

    def update(self):
        self.populateFunctionTable()

    def handleSpinThresholdChange(self):
        self.update()

    def importSelectedLabels(self):
        # get currently selected names from all dropdowns in the table
        num_names_applied = 0
        for row_id in range(self.table_local_functions.rowCount()):
            offset = int(self.table_local_functions.item(row_id, 0).text(), 16)
            label_via_table = self.table_local_functions.item(row_id, 5).text()
            result_label = label_via_table
            label_via_mapping = "-"
            map_entry = self.function_name_mapping[(row_id, 5)]
            if len(map_entry) > 0:
                label_via_mapping = map_entry[0]
            if label_via_table == "-":
                result_label = label_via_mapping
            # we did not get a usable label, so we continue to the next row
            if result_label == "-":
                continue
            # extract the actual name from the score|name pair
            result_label = result_label.split("|")[1]
            # check if IDA function has default name
            ida_function_name = ida_funcs.get_func_name(offset)
            if re.match("sub_[0-9A-Fa-f]+$", ida_function_name):
                # apply label
                self.cc.ida_proxy.set_name(offset, result_label, self.cc.ida_proxy.SN_NOWARN)
                num_names_applied += 1
        if num_names_applied:
            self.parent.local_widget.updateActivityInfo(f"Success! Imported {num_names_applied} function names.")
        else:
            self.parent.local_widget.updateActivityInfo(f"No suitable function names found to import.")

    def _updateLabelFunctionMatches(self, num_functions_matched):
        local_smda_report = self.parent.getLocalSmdaReport()
        total_local_functions = local_smda_report.num_functions
        self.label_local_functions.setText("Local Functions Matched (%d/%d), Remote Functions Matched: %d" % (self._countLocalMatches(), total_local_functions, self._countRemoteMatches()))

    def _countLocalMatches(self):
        local_matches = set([])
        match_report = self.parent.getMatchingReport()
        for function_match in match_report.function_matches:
            local_matches.add(function_match.function_id)
        return len(local_matches)

    def _countRemoteMatches(self):
        remote_matches = set([])
        match_report = self.parent.getMatchingReport()
        for function_match in match_report.function_matches:
            remote_matches.add(function_match.matched_function_id)
        return len(remote_matches)
    
    def ensureSpinBoxRange(self, match_report):
        # Set min/max value for score filter once
        if self.global_minimum_match_value is None:
            self.global_minimum_match_value = 100
            self.global_maximum_match_value = 0
            for function_match in match_report.function_matches:
                self.global_minimum_match_value = int(min(self.global_minimum_match_value, function_match.matched_score))
                self.global_maximum_match_value = int(max(self.global_maximum_match_value, function_match.matched_score))
            self.sb_minhash_threshold.setRange(self.global_minimum_match_value, self.global_maximum_match_value)
            self.sb_minhash_threshold.setValue(self.global_minimum_match_value)

    def populateFunctionTable(self):
        """
        Populate the function table with information about matches of local functions.
        """
        header_view = self._QtShim.get_QHeaderView()
        qt = self._QtShim.get_Qt()

        match_report = self.parent.getMatchingReport()
        if match_report is None:
            return
        self.ensureSpinBoxRange(match_report)
        threshold_value = self.sb_minhash_threshold.value()

        # count matched functions with labels
        function_entries_with_labels = {}
        if self.parent.matched_function_entries:
            for function_id, function_entry in self.parent.matched_function_entries.items():
                if function_entry.function_labels:
                    function_entries_with_labels[function_id] = function_entry

        # count labels
        function_labels = []
        for function_id, entry in function_entries_with_labels.items():
            for label in entry.function_labels:
                function_labels.append(label)

        # count matched functions
        matched_function_ids_per_function_id = {}
        matches_beyond_filters = 0
        total_matches = 0
        functions_beyond_filters = set()
        aggregated_matches = {}
        for function_match in match_report.function_matches:
            if function_match.function_id not in matched_function_ids_per_function_id:
                matched_function_ids_per_function_id[function_match.function_id] = []
            if function_match.matched_function_id not in matched_function_ids_per_function_id[function_match.function_id]:
                matched_function_ids_per_function_id[function_match.function_id].append(function_match.matched_function_id)
            if function_match.matched_score >= threshold_value:
                if self.cb_labels_only.isChecked() and not function_match.matched_function_id in function_entries_with_labels:
                    continue
                matches_beyond_filters += 1
                functions_beyond_filters.add(function_match.function_id)
                if function_match.function_id not in aggregated_matches:
                    aggregated_matches[function_match.function_id] = {
                        "offset": function_match.offset,
                        "families": set(),
                        "samples": set(),
                        "functions": set(),
                        "library_matches": set(),
                        "labels": set()
                    }
                aggregated_matches[function_match.function_id]["families"].add(function_match.matched_family_id)
                aggregated_matches[function_match.function_id]["samples"].add(function_match.matched_sample_id)
                aggregated_matches[function_match.function_id]["functions"].add(function_match.matched_function_id)
                if function_match.match_is_library:
                    aggregated_matches[function_match.function_id]["library_matches"].add(function_match.matched_function_id)
                if function_match.matched_function_id in function_entries_with_labels:
                    for label in function_entries_with_labels[function_match.matched_function_id].function_labels:
                        aggregated_matches[function_match.function_id]["labels"].add((int(function_match.matched_score), label.function_label))

        # Update summary
        update_text = f"Showing {len(functions_beyond_filters)} functions with {matches_beyond_filters} matches and {len(function_labels)} labels ({len(matched_function_ids_per_function_id) - len(functions_beyond_filters)} functions and {len(match_report.function_matches) - matches_beyond_filters} matches filtered)"
        self.label_local_functions.setText(update_text)
        
        self.table_local_functions.setSortingEnabled(False)
        self.local_function_header_labels = ["Offset", "Families", "Samples", "Functions", "Lib", "Score & Labels"]
        self.table_local_functions.clear()
        self.table_local_functions.setColumnCount(len(self.local_function_header_labels))
        self.table_local_functions.setHorizontalHeaderLabels(self.local_function_header_labels)
        # Identify number of table entries and prepare addresses to display
        self.table_local_functions.setRowCount(len(aggregated_matches))
        self.table_local_functions.resizeRowToContents(0)
        row = 0
        first_function = None
        self.function_name_mapping = {}
        for function_id, function_info in sorted(aggregated_matches.items()):
            self.function_name_mapping[(row, 5)] = [f"{label_entry[0]}|{label_entry[1]}" for label_entry in sorted(function_info["labels"], reverse=True)]
            for column, column_name in enumerate(self.local_function_header_labels):
                tmp_item = None
                if column == 0:
                    tmp_item = self.cc.QTableWidgetItem("0x%x" % function_info["offset"])
                elif column == 1:
                    tmp_item = self.NumberQTableWidgetItem("%d" % len(function_info["families"]))
                elif column == 2:
                    tmp_item = self.NumberQTableWidgetItem("%d" % len(function_info["samples"]))
                elif column == 3:
                    tmp_item = self.NumberQTableWidgetItem("%d" % len(function_info["functions"]))
                elif column == 4:
                    library_value = "YES" if len(function_info["library_matches"]) > 0 else "NO"
                    tmp_item = self.cc.QTableWidgetItem("%s" % library_value)
                elif column == 5:
                    label_value = "-"
                    tmp_item = self.cc.QTableWidgetItem("%s" % label_value)  
                tmp_item.setFlags(tmp_item.flags() & ~self.cc.QtCore.Qt.ItemIsEditable)
                tmp_item.setTextAlignment(qt.AlignHCenter)
                self.table_local_functions.setItem(row, column, tmp_item)
            self.table_local_functions.resizeRowToContents(row)
            row += 1
        # we need to set up rendering delegates for function names only if we have names at all
        if function_labels:
            # Set the delegate to create dropdown menus in the second column
            delegate = DropdownDelegate(self.function_name_mapping)
            self.table_local_functions.setItemDelegateForColumn(5, delegate)

            # Show the dropdown menus immediately
            for row in range(self.table_local_functions.rowCount()):
                item = self.table_local_functions.item(row, 5)  # Get the QTableWidgetItem for the cell
                self.table_local_functions.openPersistentEditor(item)

        self.table_local_functions.setSelectionMode(self.cc.QAbstractItemView.SingleSelection)
        self.table_local_functions.resizeColumnsToContents()
        self.table_local_functions.setSortingEnabled(True)
        header = self.table_local_functions.horizontalHeader()
        for header_id in range(0, len(self.local_function_header_labels), 1):
            try:
                header.setSectionResizeMode(header_id, header_view.Stretch)
            except:
                header.setResizeMode(header_id, header_view.Stretch)
        header.setStretchLastSection(True)

################################################################################
# Buttons and Actions
################################################################################

    def _onTableFunctionsSelectionChanged(self, selected, deselected):
        try:
            selected_row = self.table_local_functions.selectedItems()[0].row()
            function_offset = int(self.table_local_functions.item(selected_row, 0).text(), 16)
        except IndexError:
            # we can ignore this, as it may happen when a popup window is closed
            pass

    def _onTableFunctionsClicked(self, mi):
        """
        If a row in the best family match table is clicked, adjust the family sample match table
        """
        clicked_function_address = self.table_local_functions.item(mi.row(), 0).text()
        as_int = int(clicked_function_address, 16)
        self.last_function_selected = as_int
        print("clicked function_offset", as_int)

    def _onTableFunctionsDoubleClicked(self, mi):
        if mi.column() == 0:
            clicked_function_address = self.table_local_functions.item(mi.row(), 0).text()
            print("double clicked_function_address", clicked_function_address)
            self.cc.ida_proxy.Jump(int(clicked_function_address, 16))
            # change to function scope tab
            self.parent.main_widget.tabs.setCurrentIndex(1)
            self.parent.function_match_widget.queryCurrentFunction()
        elif mi.column() == 6:
            print("possibly apply name to function")
            clicked_label = self.table_local_functions.item(mi.row(), 6).text()
            pass
