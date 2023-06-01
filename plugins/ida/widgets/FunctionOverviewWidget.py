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
        self.cb_labels_only = self.cc.QCheckBox("Filter to Functions with Labels only")
        self.cb_labels_only.setChecked(False)
        self.cb_labels_only.stateChanged.connect(self.populateFunctionTable)
        self.b_import_labels = self.cc.QPushButton("Import all labels for unnamed functions")
        # TODO implement an actual import function here
        self.b_import_labels.clicked.connect(self.populateFunctionTable)
        self.sb_minhash_threshold = self.cc.QSpinBox()
        # horizontal line
        self.hline = self.cc.QFrame()
        self.hline.setFrameShape(self.hline.HLine)
        self.hline.setFrameShadow(self.hline.Sunken)
        # upper table
        self.label_local_functions = self.cc.QLabel("Functions Matched")
        self.table_local_functions = self.cc.QTableWidget()
        self.table_local_functions.selectionModel().selectionChanged.connect(self._onTableFunctionsSelectionChanged)
        self.table_local_functions.clicked.connect(self._onTableFunctionsClicked)
        self.table_local_functions.doubleClicked.connect(self._onTableFunctionsDoubleClicked)
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

    def update(self):
        # TODO
        # implement this in a way that we are not pulling function matches for each time we refresh,
        # instead cache them locally, similar to the SMDA report and other results
        self.populateFunctionTable()

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

    def populateFunctionTable(self):
        """
        Populate the function table with information about matches of local functions.
        """
        header_view = self._QtShim.get_QHeaderView()
        qt = self._QtShim.get_Qt()

        match_report = self.parent.getMatchingReport()
        if match_report is None:
            return
        matched_function_ids = set()
        global_minimum_match_value = 100
        global_maximum_match_value = 0
        matched_function_ids_per_function_id = {}
        for function_match in match_report.function_matches:
            global_minimum_match_value = min(global_minimum_match_value, function_match.matched_score)
            global_maximum_match_value = max(global_maximum_match_value, function_match.matched_score)
            matched_function_ids.add(function_match.matched_function_id)
            if function_match.function_id not in matched_function_ids_per_function_id:
                matched_function_ids_per_function_id[function_match.function_id] = []
            if function_match.matched_function_id not in matched_function_ids_per_function_id[function_match.function_id]:
                matched_function_ids_per_function_id[function_match.function_id].append(function_match.matched_function_id)
        if match_report.function_matches:
            self.sb_minhash_threshold.setRange(global_minimum_match_value, global_maximum_match_value)
        print("Number of matched remote functions: ", len(matched_function_ids))

        function_entries_with_labels = self.parent.mcrit_interface.queryFunctionEntriesById(list(matched_function_ids), with_label_only=True)
        function_labels = []
        for function_id, entry in function_entries_with_labels.items():
            for label in entry.function_labels:
                print(label)
                function_labels.append(label)
        print("fetched function entries, labels:", len(function_labels))
        self.table_local_functions.setSortingEnabled(False)
        self.local_function_header_labels = ["Offset", "Families", "Samples", "Functions", "Match Score", "Lib", "Labels"]
        self.table_local_functions.clear()
        self.table_local_functions.setColumnCount(len(self.local_function_header_labels))
        self.table_local_functions.setHorizontalHeaderLabels(self.local_function_header_labels)
        # Identify number of table entries and prepare addresses to display
        aggregated = match_report.getAggregatedFunctionMatches()
        self.table_local_functions.setRowCount(len(aggregated))
        # if we filter to labeled functions, we need to know how many of them have labels first
        if self.cb_labels_only.isChecked():
            num_functions_with_labels = 0
            for index, function_info in enumerate(aggregated):
                identified_names = []
                for other_function_id in matched_function_ids_per_function_id[function_info["function_id"]]:
                    if other_function_id in function_entries_with_labels:
                        for function_label in function_entries_with_labels[other_function_id].function_labels:
                            identified_names.append(function_label.function_label)
                if identified_names:
                    num_functions_with_labels += 1
            self.table_local_functions.setRowCount(num_functions_with_labels)

        self.table_local_functions.resizeRowToContents(0)
        row = 0
        first_function = None
        function_name_mapping = {}
        for index, function_info in enumerate(aggregated):
            # TODO in any case, these function names should be sorted by their associated score
            # continue here
            identified_names = []
            for other_function_id in matched_function_ids_per_function_id[function_info["function_id"]]:
                if other_function_id in function_entries_with_labels:
                    for function_label in function_entries_with_labels[other_function_id].function_labels:
                        identified_names.append(function_label.function_label)
            if self.cb_labels_only.isChecked() and not identified_names:
                continue
            function_name_mapping[(row, 6)] = list(set(identified_names))
            for column, column_name in enumerate(self.local_function_header_labels):
                tmp_item = None
                if column == 0:
                    tmp_item = self.cc.QTableWidgetItem("0x%x" % function_info["offset"])
                elif column == 1:
                    tmp_item = self.NumberQTableWidgetItem("%d" % function_info["num_families_matched"])
                elif column == 2:
                    tmp_item = self.NumberQTableWidgetItem("%d" % function_info["num_samples_matched"])
                elif column == 3:
                    tmp_item = self.NumberQTableWidgetItem("%d" % function_info["num_functions_matched"])
                elif column == 4:
                    tmp_item = self.NumberQTableWidgetItem("%d" % function_info["best_score"])
                elif column == 5:
                    library_value = "YES" if function_info["library_matches"] > 0 else "NO"
                    tmp_item = self.cc.QTableWidgetItem("%s" % library_value)
                elif column == 6:
                    label_value = "-"
                    tmp_item = self.cc.QTableWidgetItem("%s" % label_value)  
                tmp_item.setFlags(tmp_item.flags() & ~self.cc.QtCore.Qt.ItemIsEditable)
                tmp_item.setTextAlignment(qt.AlignHCenter)
                self.table_local_functions.setItem(row, column, tmp_item)
            self.table_local_functions.resizeRowToContents(row)
            row += 1

        print(function_name_mapping)
        # Set the delegate to create dropdown menus in the second column
        delegate = DropdownDelegate(function_name_mapping)
        self.table_local_functions.setItemDelegateForColumn(6, delegate)

        # Show the dropdown menus immediately
        for row in range(self.table_local_functions.rowCount()):
            item = self.table_local_functions.item(row, 6)  # Get the QTableWidgetItem for the cell
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
        selected_row = self.table_local_functions.selectedItems()[0].row()
        function_offset = int(self.table_local_functions.item(selected_row, 0).text(), 16)

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
            self.parent.main_widget.tabs.setCurrentIndex(0)
            self.parent.function_match_widget.queryCurrentFunction()
        elif mi.column() == 6:
            print("possibly apply name to function")
            clicked_label = self.table_local_functions.item(mi.row(), 6).text()
            pass
