import datetime

import helpers.QtShim as QtShim
QMainWindow = QtShim.get_QMainWindow()


class LocalInfoWidget(QMainWindow):

    def __init__(self, parent):
        self.cc = parent.cc
        self.cc.QMainWindow.__init__(self)
        self._datetime = datetime
        print("[|] loading LocalInfoWidget")
        # enable access to shared MCRIT4IDA modules
        self.parent = parent
        self.name = "LocalInfo"
        self.icon = self.cc.QIcon(self.parent.config.ICON_FILE_PATH + "inspection.png")
        self.central_widget = self.cc.QWidget()
        self.setCentralWidget(self.central_widget)
        self.label_mcrit_activity_info = self.cc.QLabel("Activity Info: <PLACEHOLDER>")
        self.updateActivityInfo("MCRIT4IDA started.")
        self.label_mcrit_server_info = self.cc.QLabel("MCRIT Remote server: <not_active>")
        self.label_remote_sample_info = self.cc.QLabel("Remote sample: <unknown>")
        # horizontal line
        self.hline = self.cc.QFrame()
        self.hline.setFrameShape(self.cc.QFrameHLine)
        self.hline.setFrameShadow(self.cc.QFrameShadow.Sunken)
        # SMDA report info fields
        self.label_sha256 = self.cc.QLabel("SHA256: ")
        self.label_label_sha256_value = self.cc.QLabel("no data")
        self.label_architecture = self.cc.QLabel("Architecture: ")
        self.label_architecture_value = self.cc.QLabel("no data")
        self.label_bitness = self.cc.QLabel("Bitness: ")
        self.label_bitness_value = self.cc.QLabel("no data")
        self.label_image_base = self.cc.QLabel("ImageBase: ")
        self.label_image_base_value = self.cc.QLabel("no data")
        self.label_functions = self.cc.QLabel("Functions: ")
        self.label_functions_value = self.cc.QLabel("no data")
        self.label_instructions = self.cc.QLabel("Instructions: ")
        self.label_instructions_value = self.cc.QLabel("no data")
        self.label_size = self.cc.QLabel("Code Size: ")
        self.label_size_value = self.cc.QLabel("no data")
        self.label_family = self.cc.QLabel("Family: ")
        self.label_family_value = self.cc.QLabel("no data")
        self.label_version = self.cc.QLabel("Version: ")
        self.label_version_value = self.cc.QLabel("no data")
        self.label_library = self.cc.QLabel("Library: ")
        self.label_library_value = self.cc.QLabel("no data")
        self._createGui()

    def _createGui(self):
        """
        Setup function for the full GUI of this widget.
        """
        # compose and layout the widget
        local_layout = self.cc.QVBoxLayout()
        local_layout.addWidget(self.label_mcrit_activity_info)
        local_layout.addWidget(self.label_mcrit_server_info)
        local_layout.addWidget(self.label_remote_sample_info)
        local_layout.addWidget(self.hline)
        local_info_widget = self.cc.QWidget()
        grid_layout = self.cc.QGridLayout()
        grid_layout.addWidget(self.label_sha256, 0, 0)
        grid_layout.addWidget(self.label_label_sha256_value, 0, 1)
        grid_layout.addWidget(self.label_architecture, 1, 0)
        grid_layout.addWidget(self.label_architecture_value, 1, 1)
        grid_layout.addWidget(self.label_bitness, 2, 0)
        grid_layout.addWidget(self.label_bitness_value, 2, 1)
        grid_layout.addWidget(self.label_image_base, 3, 0)
        grid_layout.addWidget(self.label_image_base_value, 3, 1)
        grid_layout.addWidget(self.label_functions, 4, 0)
        grid_layout.addWidget(self.label_functions_value, 4, 1)
        grid_layout.addWidget(self.label_instructions, 5, 0)
        grid_layout.addWidget(self.label_instructions_value, 5, 1)
        grid_layout.addWidget(self.label_size, 6, 0)
        grid_layout.addWidget(self.label_size_value, 6, 1)
        grid_layout.addWidget(self.label_family, 7, 0)
        grid_layout.addWidget(self.label_family_value, 7, 1)
        grid_layout.addWidget(self.label_version, 8, 0)
        grid_layout.addWidget(self.label_version_value, 8, 1)
        grid_layout.addWidget(self.label_library, 9, 0)
        grid_layout.addWidget(self.label_library_value, 9, 1)
        grid_layout.setColumnStretch(0, 1)
        grid_layout.setColumnStretch(1, 3)
        local_info_widget.setLayout(grid_layout)
        local_layout.addWidget(local_info_widget)
        self.central_widget.setLayout(local_layout)

    def _summarizeLocalReportInstructionBytes(self):
        num_bytes = 0
        local_smda_report = self.parent.getLocalSmdaReport()
        if local_smda_report:
            for smda_function in local_smda_report.getFunctions():
                    for smda_ins in smda_function.getInstructions():
                        num_bytes += len(smda_ins.bytes) / 2
        return num_bytes

    def update(self):
        local_smda_report = self.parent.getLocalSmdaReport()
        self.label_label_sha256_value.setText(local_smda_report.sha256)
        self.label_architecture_value.setText(local_smda_report.architecture)
        self.label_bitness_value.setText("%d bit" % local_smda_report.bitness)
        self.label_image_base_value.setText("0x%x" % local_smda_report.base_addr)
        self.label_functions_value.setText("%d (leaf: %d, recursive: %d)" % (local_smda_report.num_functions, local_smda_report.statistics.num_leaf_functions, local_smda_report.statistics.num_recursive_functions))
        self.label_instructions_value.setText("%d" % (local_smda_report.statistics.num_instructions))
        self.label_size_value.setText("%d bytes" % self._summarizeLocalReportInstructionBytes())
        self.label_family_value.setText(local_smda_report.family)
        self.label_version_value.setText(local_smda_report.version)
        is_library = "YES" if local_smda_report.is_library else "NO"
        self.label_library_value.setText(is_library)
        if self.parent.remote_sample_entry:
            self.label_remote_sample_info.setText("Remote sample: %s (%s -- %s)" % (self.parent.remote_sample_entry.sample_id, self.parent.remote_sample_entry.family, self.parent.remote_sample_entry.version))

    def updateActivityInfo(self, message):
        timestamp = self._datetime.datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%SZ")
        self.label_mcrit_activity_info.setText("Activity Info: %s - %s" % (timestamp, message))

    def updateServerInfo(self, mcrit_server, version=None, statistics=None):
        if statistics:
            num_families = statistics["num_families"]
            fam_str = "families" if num_families != 1 else "family"
            num_samples = statistics["num_samples"]
            sam_str = "samples" if num_samples != 1 else "sample"
            num_functions = statistics["num_functions"]
            fun_str = "functions" if num_functions != 1 else "function"
        version_text = version if version is not None else "No connection"
        status_text = "Content: %d %s with %d %s containing %d %s." % (num_families, fam_str, num_samples, sam_str, num_functions, fun_str) if statistics else "No statistics"
        self.label_mcrit_server_info.setText("Remote server: %s  -- %s -- %s." % (mcrit_server, version_text, status_text))
