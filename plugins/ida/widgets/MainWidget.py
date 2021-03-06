import json
import os

import idaapi
import idc

import helpers.QtShim as QtShim
QMainWindow = QtShim.get_QMainWindow()

from widgets.SmdaInfoDialog import SmdaInfoDialog


class MainWidget(QMainWindow):

    def __init__(self, parent):
        self.cc = parent.cc
        self.cc.QMainWindow.__init__(self)
        print("[|] loading MainWidget")
        # enable access to shared MCRIT4IDA modules
        self.parent = parent
        self.name = "Main"
        self.icon = self.cc.QIcon(self.parent.config.ICON_FILE_PATH + "relationship.png")
        self.tabs = None
        self.tabbed_widgets = [self.parent.sample_widget, self.parent.function_widget]
        self.central_widget = self.cc.QWidget()
        self.setCentralWidget(self.central_widget)
        self.SmdaInfoDialog = SmdaInfoDialog
        self._createGui()
        self.parent.mcrit_interface.checkConnection()
        # IDA 6.x Windows workaronud to avoid lost imports
        self.os = os
        self.os_path = os.path

    def _createGui(self):
        """
        Setup function for the full GUI of this widget.
        """
        # create the main toolbar
        self._createToolbar()
        # layout and fill the widget
        self.tabs = self.cc.QTabWidget()
        self.tabs.setTabsClosable(False)
        for widget in self.tabbed_widgets:
            self.tabs.addTab(widget, widget.icon, widget.name)
        layout = self.cc.QVBoxLayout()
        splitter = self.cc.QSplitter(self.cc.QtCore.Qt.Vertical)
        q_clean_style = self.cc.QStyleFactory.create('Plastique')
        splitter.setStyle(q_clean_style)
        splitter.addWidget(self.parent.local_widget)
        splitter.addWidget(self.tabs)
        splitter.setStretchFactor(1, 10)
        layout.addWidget(splitter)
        self.central_widget.setLayout(layout)
        self.setTabFocus("SampleInfo")

    def _createToolbar(self):
        """
        Creates the toolbar, containing buttons to control the widget.
        """
        self.toolbar = self.addToolBar('MCRIT4IDA Toobar')
        self._createParseSmdaAction()
        self.toolbar.addAction(self.parseSmdaAction)
        self._createExportSmdaAction()
        self.toolbar.addAction(self.exportSmdaAction)
        self._createUploadSmdaAction()
        self.toolbar.addAction(self.uploadSmdaAction)
        self._createQueryMcritAction()
        self.toolbar.addAction(self.queryMcritAction)
        self._createModifySettingsAction()
        self.toolbar.addAction(self.modifySettingsAction)

    def _createParseSmdaAction(self):
        """
        Create an action for parsing the IDB into a SMDA report.
        """
        self.parseSmdaAction = self.cc.QAction(self.cc.QIcon(self.parent.config.ICON_FILE_PATH + "fingerprint_scan.png"), \
            "Convert this IDB to SMDA report that can be used to query MCRIT.", self)
        self.parseSmdaAction.triggered.connect(self._onConvertSmdaButtonClicked)


    def _createExportSmdaAction(self):
        """
        Create an action for exporting the parsed SMDA report into json/smda format.
        """
        self.exportSmdaAction = self.cc.QAction(self.cc.QIcon(self.parent.config.ICON_FILE_PATH + "export.png"), \
            "Export the SMDA report to local disk.", self)
        self.exportSmdaAction.triggered.connect(self._onExportSmdaButtonClicked)

    def _createUploadSmdaAction(self):
        """
        Create an action for uploading the parsed SMDA report to the server.
        TODO: will require addition of some more meta data.
        """
        self.uploadSmdaAction = self.cc.QAction(self.cc.QIcon(self.parent.config.ICON_FILE_PATH + "upload.png"), \
            "Upload the parsed SMDA report to the MCRIT server.", self)
        self.uploadSmdaAction.triggered.connect(self._onUploadSmdaButtonClicked)

    def _createQueryMcritAction(self):
        """
        Create an action for sending a matching query to the MCRIT server.
        """
        self.queryMcritAction = self.cc.QAction(self.cc.QIcon(self.parent.config.ICON_FILE_PATH + "satellite_dish.png"), \
            "Query MCRIT with the parsed SDMA report.", self)
        self.queryMcritAction.triggered.connect(self._onQueryMcritButtonClicked)

    def _createModifySettingsAction(self):
        """
        Create an action for sending a matching query to the MCRIT server.
        """
        self.modifySettingsAction = self.cc.QAction(self.cc.QIcon(self.parent.config.ICON_FILE_PATH + "settings.png"), \
            "Adjust MCRIT4IDA settings.", self)
        self.modifySettingsAction.triggered.connect(self._onNopButtonClicked)

    def _onNopButtonClicked(self):
        return

    def _onExportSmdaButtonClicked(self):
        if self.parent.local_smda_report:
            filepath = idc.AskFile(1, self.parent.local_smda_report["filename"] + ".smda", 'Export SMDA report to file...')
            if filepath:
                with open(filepath, "w") as fout:
                    json.dump(self.parent.local_smda_report, fout, indent=1, sort_keys=True)
                self.parent.local_widget.updateActivityInfo("IDB exported to: \"%s\"." % filepath)
            else:
                self.parent.local_widget.updateActivityInfo("Export aborted.")
        else:
            self.parent.local_widget.updateActivityInfo("IDB is not converted to SMDA report yet, can't export.")

    def _onUploadSmdaButtonClicked(self):
        if self.parent.local_smda_report:
            self.parent.mcrit_interface.uploadReport(self.parent.local_smda_report)
        else:
            self.parent.local_widget.updateActivityInfo("IDB is not converted to SMDA report yet, can't upload.")

    def _onConvertSmdaButtonClicked(self):
        self.parent.local_smda_report = self.parent.mcrit_interface.convertIdbToSmda()
        dialog = self.SmdaInfoDialog(self)
        dialog.exec_()
        smda_info = dialog.getSmdaInfo()
        if self.parent.local_smda_report:
            self.parent.local_smda_report["filename"] = self.os_path.basename(idaapi.get_root_filename())
            self.parent.local_smda_report["sha256"] = idaapi.retrieve_input_file_sha256().hex()
            self.parent.local_smda_report["buffer_size"] = idaapi.retrieve_input_file_size()
            self.parent.local_smda_report["metadata"]["family"] = smda_info["family"]
            self.parent.local_smda_report["metadata"]["version"] = smda_info["version"]
            self.parent.local_smda_report["metadata"]["is_library"] = smda_info["is_library"]
            self.parent.local_smda_report["metadata"]["source"] = "MCRIT4IDA v%s" % self.parent.config.VERSION
        self.parent.local_widget.update()

    def _onQueryMcritButtonClicked(self):
        if self.parent.remote_sample_id is not None:
            self.parent.mcrit_interface.queryMatchReport(self.parent.remote_sample_id)
            self.parent.mcrit_interface.querySampleInfos()
            self.parent.mcrit_interface.queryFunctionInfos(self.parent.remote_sample_id)
            self.parent.sample_widget.populateBestMatchTable()
            self.parent.function_widget.populateLocalFunctionTable()
        else:
            self.parent.local_widget.updateActivityInfo("Sample not uploaded yet, can't query results.")

    def setTabFocus(self, widget_name):
        """
        Can be used by MCRIT4IDA widgets to set focus to a widget, identified by name.
        @param widget_name: A widget name
        @type widget_name: str
        """
        for widget in self.tabbed_widgets:
            if widget.name == widget_name:
                tab_index = self.tabs.indexOf(widget)
                self.tabs.setCurrentIndex(tab_index)
        return
