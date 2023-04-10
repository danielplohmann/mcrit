import helpers.QtShim as QtShim
from widgets.NumberQTableWidgetItem import NumberQTableWidgetItem

QMainWindow = QtShim.get_QMainWindow()


class FunctionInfoWidget(QMainWindow):

    def __init__(self, parent):
        self.cc = parent.cc
        self.cc.QMainWindow.__init__(self)
        print("[|] loading FunctionInfoWidget")
        # enable access to shared MCRIT4IDA modules
        self.parent = parent
        self.name = "Function Match Summary"
        self.last_function_selected = None
        self.icon = self.cc.QIcon(self.parent.config.ICON_FILE_PATH + "relationship.png")
        self.central_widget = self.cc.QWidget()
        self.setCentralWidget(self.central_widget)
        self.cb_filter_library = self.cc.QCheckBox("Filter to Library Function Matches")
        self.cb_filter_library.setChecked(False)
        self.cb_filter_library.stateChanged.connect(self.populateLocalFunctionTable)
        self.cb_show_family = self.cc.QCheckBox("Show Family Matches (instead of Sample)")
        self.cb_show_family.setChecked(False)
        self.cb_show_family.stateChanged.connect(self.populateLocalFunctionTable)
        self.cb_aggregate_multimatches = self.cc.QCheckBox("Aggregate MultiMatches for Samples")
        self.cb_aggregate_multimatches.setChecked(False)
        self.cb_aggregate_multimatches.setEnabled(False)
        self.cb_aggregate_multimatches.stateChanged.connect(self.populateFunctionMatchTable)
        self.sb_minhash_threshold = self.cc.QSpinBox()
        # TODO add chooser for lower minhash threshold
        # horizontal line
        self.hline = self.cc.QFrame()
        self.hline.setFrameShape(self.hline.HLine)
        self.hline.setFrameShadow(self.hline.Sunken)
        # upper table
        self.label_local_functions = self.cc.QLabel("Local Functions Matched:")
        self.table_local_functions = self.cc.QTableWidget()
        self.table_local_functions.selectionModel().selectionChanged.connect(self._onTableLocalFunctionsSelectionChanged)
        self.table_local_functions.clicked.connect(self._onTableLocalFunctionsClicked)
        self.table_local_functions.doubleClicked.connect(self._onTableLocalFunctionsDoubleClicked)
        # lower table
        self.label_function_matches = self.cc.QLabel("Matches for function:")
        self.table_function_matches = self.cc.QTableWidget()
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
        function_info_layout.addWidget(self.cb_filter_library)
        function_info_layout.addWidget(self.cb_show_family)
        function_info_layout.addWidget(self.cb_aggregate_multimatches)
        function_info_layout.addWidget(self.hline)
        function_info_layout.addWidget(self.label_local_functions)
        function_info_layout.addWidget(self.table_local_functions)
        function_info_layout.addWidget(self.label_function_matches)
        function_info_layout.addWidget(self.table_function_matches)
        self.central_widget.setLayout(function_info_layout)

################################################################################
# Rendering and state keeping
################################################################################

    def update(self):
        self.populateBestMatchTable()
        self.updateFunctionsLabel()

    def _updateLabelLocalFunctionMatches(self, num_functions_matched):
        local_smda_report = self.parent.getLocalSmdaReport()
        total_local_functions = local_smda_report.num_functions
        remote_matches = self._countRemoteMatches()
        self.label_local_functions.setText("Local Functions Matched (%d/%d), Remote Functions Matched: %d" % (num_functions_matched, total_local_functions, remote_matches))

    def _updateLabelFunctionMatches(self, selected_function_id):
        selected_function_id = str(selected_function_id)
        function_infos = self.parent.getFunctionInfos()
        selected_offset = 0
        selected_name = ""
        if selected_function_id in function_infos:
            selected_offset = function_infos[selected_function_id]["offset"]
            name = function_infos[selected_function_id]["function_name"]
            selected_name = " (%s)" % name if name else ""
        self.label_function_matches.setText("Matches for Function ID: %s @0x%x%s" % (selected_function_id, selected_offset, selected_name))

    def _countRemoteMatches(self):
        remote_matches = set([])
        match_report = self.parent.getMatchingReport()
        for own_function_id, match_data in match_report["pichash"]["pichash_matches"].items():
            for foreign_sample_id, foreign_matches in match_data["matches"].items():
                for match in foreign_matches:
                    remote_matches.add(match[0])
        for own_function_id, match_data in match_report["minhash"]["minhash_matches"].items():
            for foreign_sample_id, foreign_matches in match_data["matches"].items():
                foreign_sample_id = int(foreign_sample_id)
                for match in foreign_matches:
                    remote_matches.add(match[0])
        return len(remote_matches)

    def _aggregatedLocalFunctionMatchingData(self):
        """ TODO refactor to somewhere else or re-use from mcrit core """
        match_report = self.parent.getMatchingReport()
        sample_infos = self.parent.getSampleInfos()
        function_infos = self.parent.getFunctionInfos()
        local_function_matches = {}
        for own_function_id, match_data in match_report["pichash"]["pichash_matches"].items():
            int_own_function_id = int(own_function_id)
            if int_own_function_id not in local_function_matches:
                local_function_matches[int_own_function_id] = {
                    "pichash_families": set([]),
                    "pichash_samples": set([]),
                    "minhash_families": set([]),
                    "minhash_samples": set([]),
                    "is_library": False,
                    "function_id": int_own_function_id,
                    "function_offset": function_infos[own_function_id]["offset"],
                    "function_name": function_infos[own_function_id]["function_name"],
                    "num_instructions": function_infos[own_function_id]["num_instructions"]
                }
            for foreign_sample_id, foreign_matches in match_data["matches"].items():
                foreign_sample_id = int(foreign_sample_id)
                foreign_family = sample_infos[foreign_sample_id]["family"]
                local_function_matches[int_own_function_id]["pichash_samples"].add(foreign_sample_id)
                local_function_matches[int_own_function_id]["pichash_families"].add(foreign_family)
                if match_data["has_library_match"]:
                    local_function_matches[int_own_function_id]["is_library"] = True
        for own_function_id, match_data in match_report["minhash"]["minhash_matches"].items():
            int_own_function_id = int(own_function_id)
            if int_own_function_id not in local_function_matches:
                local_function_matches[int_own_function_id] = {
                    "pichash_families": set([]),
                    "pichash_samples": set([]),
                    "minhash_families": set([]),
                    "minhash_samples": set([]),
                    "is_library": False,
                    "function_id": int_own_function_id,
                    "function_offset": function_infos[own_function_id]["offset"],
                    "function_name": function_infos[own_function_id]["function_name"],
                    "num_instructions": function_infos[own_function_id]["num_instructions"]
                }
            for foreign_sample_id, foreign_matches in match_data["matches"].items():
                foreign_sample_id = int(foreign_sample_id)
                foreign_family = sample_infos[foreign_sample_id]["family"]
                local_function_matches[int_own_function_id]["minhash_samples"].add(foreign_sample_id)
                local_function_matches[int_own_function_id]["minhash_families"].add(foreign_family)
                if match_data["has_library_match"]:
                    local_function_matches[int_own_function_id]["is_library"] = True
        return local_function_matches

    def getMatchDataForFunctionId(self, function_id):
        """ TODO refactor to somewhere else or re-use from mcrit core """
        match_report = self.parent.getMatchingReport()
        sample_infos = self.parent.getSampleInfos()
        function_matches = {}
        function_id = str(function_id)
        if function_id in match_report["pichash"]["pichash_matches"]:
            function_match_data = match_report["pichash"]["pichash_matches"][function_id]
            for foreign_sample_id, foreign_matches in function_match_data["matches"].items():
                foreign_sample_id = int(foreign_sample_id)
                sha256 = sample_infos[foreign_sample_id]["sha256"]
                family = sample_infos[foreign_sample_id]["family"]
                version = sample_infos[foreign_sample_id]["version"]
                is_library = sample_infos[foreign_sample_id]["is_library"]
                for match in foreign_matches:
                    foreign_function_id = match[0]
                    if foreign_function_id not in function_matches:
                        function_matches[foreign_function_id] = {
                            "sha256": sha256,
                            "family": family,
                            "version": version,
                            "sample_id": foreign_sample_id,
                            "pichash_score": 100,
                            "minhash_score": 0,
                            "function_name": "TODO",
                            "is_library": is_library
                        }
        if function_id in match_report["minhash"]["minhash_matches"]:
            function_match_data = match_report["minhash"]["minhash_matches"][function_id]
            for foreign_sample_id, foreign_matches in function_match_data["matches"].items():
                foreign_sample_id = int(foreign_sample_id)
                sha256 = sample_infos[foreign_sample_id]["sha256"]
                family = sample_infos[foreign_sample_id]["family"]
                version = sample_infos[foreign_sample_id]["version"]
                is_library = sample_infos[foreign_sample_id]["is_library"]
                for match in foreign_matches:
                    foreign_function_id = match[0]
                    if foreign_function_id not in function_matches:
                        function_matches[foreign_function_id] = {
                            "sha256": sha256,
                            "family": family,
                            "version": version,
                            "sample_id": foreign_sample_id,
                            "pichash_score": 0,
                            "minhash_score": match[1],
                            "function_name": "TODO",
                            "is_library": is_library
                        }
                    else:
                        function_matches[foreign_function_id]["minhash_match"] = match[1]

        return function_matches

    def populateLocalFunctionTable(self):
        """
        Populate the local function table with information about matches of local functions.
        """
        header_view = self._QtShim.get_QHeaderView()
        qt = self._QtShim.get_Qt()

        matching_data = self._aggregatedLocalFunctionMatchingData()
        self.table_local_functions.setSortingEnabled(False)
        minhash_label = "MinHash (Family)" if self.cb_show_family.isChecked() else "MinHash (Sample)"
        pichash_label = "PicHash (Family)" if self.cb_show_family.isChecked() else "PicHash (Sample)"
        combined_label = "Combined (Family)" if self.cb_show_family.isChecked() else "Combined (Sample)"
        self.local_function_header_labels = ["ID", "Offset", "Name", "Instructions", minhash_label, pichash_label, combined_label, "Library"]
        self.table_local_functions.clear()
        self.table_local_functions.setColumnCount(len(self.local_function_header_labels))
        self.table_local_functions.setHorizontalHeaderLabels(self.local_function_header_labels)
        # Identify number of table entries and prepare addresses to display
        num_library_matches = len([k for k, v in matching_data.items() if v["is_library"]])
        num_functions_matched = num_library_matches if self.cb_filter_library.isChecked() else len(matching_data)
        self._updateLabelLocalFunctionMatches(num_functions_matched)
        self.table_local_functions.setRowCount(num_functions_matched)
        self.table_local_functions.resizeRowToContents(0)
        row = 0
        first_function = None
        for function_id, function_entry in sorted(matching_data.items(), key=lambda x: x[1]["function_offset"]):
            if self.cb_filter_library.isChecked() and not function_entry["is_library"]:
                continue
            if first_function is None:
                first_function = function_id
            minhash_families = function_entry["minhash_families"]
            minhash_samples = function_entry["minhash_samples"]
            pichash_families = function_entry["pichash_families"]
            pichash_samples = function_entry["pichash_samples"]
            combined_families = minhash_families.union(pichash_families)
            combined_samples = minhash_samples.union(pichash_samples)
            for column, column_name in enumerate(self.local_function_header_labels):
                tmp_item = None
                if column == 0:
                    tmp_item = self.NumberQTableWidgetItem("%d" % function_entry["function_id"])
                elif column == 1:
                    tmp_item = self.cc.QTableWidgetItem("0x%x" % function_entry["function_offset"])
                elif column == 2:
                    tmp_item = self.cc.QTableWidgetItem(function_entry["function_name"])
                elif column == 3:
                    tmp_item = self.NumberQTableWidgetItem("%d" % function_entry["num_instructions"])
                elif column == 4:
                    minhash_value = len(minhash_families) if self.cb_show_family.isChecked() else len(minhash_samples)
                    tmp_item = self.NumberQTableWidgetItem("%d" % minhash_value)
                elif column == 5:
                    pichash_value = len(pichash_families) if self.cb_show_family.isChecked() else len(pichash_samples)
                    tmp_item = self.NumberQTableWidgetItem("%d" % pichash_value)
                elif column == 6:
                    combined_value = len(combined_families) if self.cb_show_family.isChecked() else len(combined_samples)
                    tmp_item = self.NumberQTableWidgetItem("%d" % combined_value)
                elif column == 7:
                    library_value = "YES" if function_entry["is_library"] else ""
                    tmp_item = self.cc.QTableWidgetItem("%s" % library_value)
                tmp_item.setFlags(tmp_item.flags() & ~self.cc.QtCore.Qt.ItemIsEditable)
                tmp_item.setTextAlignment(qt.AlignHCenter)
                self.table_local_functions.setItem(row, column, tmp_item)
            self.table_local_functions.resizeRowToContents(row)
            row += 1
        self.table_local_functions.setSelectionMode(self.cc.QAbstractItemView.SingleSelection)
        self.table_local_functions.resizeColumnsToContents()
        self.table_local_functions.setSortingEnabled(True)
        header = self.table_local_functions.horizontalHeader()
        for header_id in range(0, len(self.local_function_header_labels), 1):
            try:
                header.setSectionResizeMode(header_id, header_view.Stretch)
            except:
                header.setResizeMode(header_id, header_view.Stretch)
        # propagate family selection to family match table
        selected_function_id = self.last_function_selected if self.last_function_selected else first_function
        selected_function_id = selected_function_id
        self._updateLabelFunctionMatches(selected_function_id)
        self.populateFunctionMatchTable(selected_function_id)

    def populateFunctionMatchTable(self, selected_function_id):
        """
        Populate the function match table with all matches for the selected function_id
        """
        matching_data = self.getMatchDataForFunctionId(selected_function_id)
        self.table_function_matches.setSortingEnabled(False)
        self.function_matches_header_labels = ["ID", "SHA256", "Sample ID", "Family", "Version", "PicHash", "MinHash", "Label", "Library"]
        self.table_function_matches.clear()
        self.table_function_matches.setColumnCount(len(self.function_matches_header_labels))
        self.table_function_matches.setHorizontalHeaderLabels(self.function_matches_header_labels)
        # Identify number of table entries and prepare addresses to display
        self._updateLabelFunctionMatches(selected_function_id)
        num_library_matches = len([k for k, v in matching_data.items() if v["is_library"]])
        num_functions_matched = num_library_matches if self.cb_filter_library.isChecked() else len(matching_data)
        self.table_function_matches.setRowCount(num_functions_matched)
        self.table_function_matches.resizeRowToContents(0)
        # TODO continue here
        row = 0
        for foreign_function_id, match_entry in sorted(matching_data.items()):
            if self.cb_filter_library.isChecked() and not match_entry["is_library"]:
                continue
            for column, column_name in enumerate(self.function_matches_header_labels):
                tmp_item = None
                if column == 0:
                    tmp_item = self.NumberQTableWidgetItem("%d" % foreign_function_id)
                elif column == 1:
                    tmp_item = self.cc.QTableWidgetItem(match_entry["sha256"])
                elif column == 2:
                    tmp_item = self.NumberQTableWidgetItem("%d" % match_entry["sample_id"])
                elif column == 3:
                    tmp_item = self.cc.QTableWidgetItem(match_entry["family"])
                elif column == 4:
                    tmp_item = self.cc.QTableWidgetItem(match_entry["version"])
                elif column == 5:
                    tmp_item = self.NumberQTableWidgetItem("%d" % match_entry["pichash_score"])
                elif column == 6:
                    tmp_item = self.NumberQTableWidgetItem("%d" % match_entry["minhash_score"])
                elif column == 7:
                    tmp_item = self.cc.QTableWidgetItem(match_entry["function_name"])
                elif column == 8:
                    library_value = "YES" if match_entry["is_library"] else ""
                    tmp_item = self.cc.QTableWidgetItem("%s" % library_value)
                tmp_item.setFlags(tmp_item.flags() & ~self.cc.QtCore.Qt.ItemIsEditable)
                self.table_function_matches.setItem(row, column, tmp_item)
            self.table_function_matches.resizeRowToContents(row)
            row += 1
        self.table_function_matches.setSelectionMode(self.cc.QAbstractItemView.SingleSelection)
        self.table_function_matches.resizeColumnsToContents()
        self.table_function_matches.setSortingEnabled(True)
        header_view = self._QtShim.get_QHeaderView()
        header = self.table_function_matches.horizontalHeader()
        for header_id in range(0, len(self.function_matches_header_labels), 1):
            try:
                header.setSectionResizeMode(header_id, header_view.Stretch)
            except:
                header.setResizeMode(header_id, header_view.Stretch)

################################################################################
# Buttons and Actions
################################################################################

    def _onTableLocalFunctionsSelectionChanged(self, selected, deselected):
        selected_row = self.table_local_functions.selectedItems()[0].row()
        function_id = int(self.table_local_functions.item(selected_row, 0).text())
        self.last_function_selected = function_id
        self.populateFunctionMatchTable(function_id)

    def _onTableLocalFunctionsClicked(self, mi):
        """
        If a row in the best family match table is clicked, adjust the family sample match table
        """
        function_id = int(self.table_local_functions.item(mi.row(), 0).text())
        self.last_function_selected = function_id
        self.populateFunctionMatchTable(function_id)

    def _onTableLocalFunctionsDoubleClicked(self, mi):
        clicked_function_address = self.table_local_functions.item(mi.row(), 1).text()
        self.cc.ida_proxy.Jump(int(clicked_function_address, 16))
