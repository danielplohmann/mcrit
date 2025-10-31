import json
import os

import idaapi
import idc
import ida_kernwin

import helpers.QtShim as QtShim
QMainWindow = QtShim.get_QMainWindow()

from widgets.SmdaInfoDialog import SmdaInfoDialog
from widgets.ResultChooserDialog import ResultChooserDialog
from widgets.YaraStringBuilderDialog import YaraStringBuilderDialog


class MainWidget(QMainWindow):

    def __init__(self, parent):
        self.cc = parent.cc
        self.cc.QMainWindow.__init__(self)
        print("[|] loading MainWidget")
        # enable access to shared MCRIT4IDA modules
        self.parent = parent
        self.name = "Main"
        self.icon = self.cc.QIcon(self.parent.config.ICON_FILE_PATH + "mcrit.png")
        self.tabs = None
        self.tabbed_widgets = [self.parent.function_match_widget, self.parent.sample_widget, self.parent.function_widget]
        self.tabbed_widgets = [self.parent.block_match_widget, self.parent.function_match_widget, self.parent.function_widget]
        self.central_widget = self.cc.QWidget()
        self.setCentralWidget(self.central_widget)
        self.SmdaInfoDialog = SmdaInfoDialog
        self.ResultChooserDialog = ResultChooserDialog
        self.YaraStringBuilderDialog = YaraStringBuilderDialog
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
        self.splitter = self.cc.QSplitter(self.cc.QtCore.Qt.Vertical)
        q_clean_style = self.cc.QStyleFactory.create('Plastique')
        self.splitter.setStyle(q_clean_style)
        self.splitter.addWidget(self.parent.local_widget)
        self.splitter.addWidget(self.tabs)
        self.splitter.setStretchFactor(1, 10)
        layout.addWidget(self.splitter)
        self.central_widget.setLayout(layout)
        self.setTabFocus("SampleInfo")

    def _createToolbar(self):
        """
        Creates the toolbar, containing buttons to control the widget.
        """
        # TODO for MCRIT 1.0.0 release, we hide the other buttons until they are properly developed
        self.toolbar = self.addToolBar('MCRIT4IDA Toobar')
        self._createParseSmdaAction()
        self.toolbar.addAction(self.parseSmdaAction)
        self._createUploadSmdaAction()
        self.toolbar.addAction(self.uploadSmdaAction)
        self._createGetMatchResultAction()
        self.toolbar.addAction(self.getMatchResultAction)
        self._createExportSmdaAction()
        self.toolbar.addAction(self.exportSmdaAction)
        self._createBuildYaraStringAction()
        self.toolbar.addAction(self.buildYaraStringAction)
        self._createModifySettingsAction()
        #self.toolbar.addAction(self.modifySettingsAction)

    def _createParseSmdaAction(self):
        """
        Create an action for parsing the IDB into a SMDA report.
        """
        self.parseSmdaAction = self.cc.QAction(self.cc.QIcon(self.parent.config.ICON_FILE_PATH + "fingerprint_scan.png"), \
            "Convert this IDB to a SMDA report which can then be used to query MCRIT.", self)
        self.parseSmdaAction.triggered.connect(self._onConvertSmdaButtonClicked)

    def _createUploadSmdaAction(self):
        """
        Create an action for uploading the parsed SMDA report to the server.
        TODO: will require addition of some more meta data.
        """
        self.uploadSmdaAction = self.cc.QAction(self.cc.QIcon(self.parent.config.ICON_FILE_PATH + "cloud-upload.png"), \
            "Reparse and upload the SMDA report to the MCRIT server.", self)
        self.uploadSmdaAction.setEnabled(False)
        self.uploadSmdaAction.triggered.connect(self._onUploadSmdaButtonClicked)

    def _createGetMatchResultAction(self):
        """
        Create an action for requesting a MatchReport for the given remote sample
        """
        self.getMatchResultAction = self.cc.QAction(self.cc.QIcon(self.parent.config.ICON_FILE_PATH + "satellite_dish.png"), \
            "Request the MatchResult for the uploaded sample.", self)
        self.getMatchResultAction.setEnabled(False)
        self.getMatchResultAction.triggered.connect(self._onGetMatchResultButtonClicked)

    def _createExportSmdaAction(self):
        """
        Create an action for exporting the parsed SMDA report into json/smda format.
        """
        self.exportSmdaAction = self.cc.QAction(self.cc.QIcon(self.parent.config.ICON_FILE_PATH + "export.png"), \
            "Export the SMDA report to local disk.", self)
        self.exportSmdaAction.setEnabled(False)
        self.exportSmdaAction.triggered.connect(self._onExportSmdaButtonClicked)

    def _createBuildYaraStringAction(self):
        """
        Create an action for building a YARA string from the current selection.
        """
        self.buildYaraStringAction = self.cc.QAction(self.cc.QIcon(self.parent.config.ICON_FILE_PATH + "yara.png"), \
            "Build a YARA string from the current selection.", self)
        self.buildYaraStringAction.setEnabled(False)
        self.buildYaraStringAction.triggered.connect(self._onBuildYaraStringButtonClicked)

    def _createModifySettingsAction(self):
        """
        Create an action for sending a matching query to the MCRIT server.
        """
        self.modifySettingsAction = self.cc.QAction(self.cc.QIcon(self.parent.config.ICON_FILE_PATH + "settings.png"), \
            "Adjust MCRIT4IDA settings.", self)
        self.modifySettingsAction.triggered.connect(self._onNopButtonClicked)

    def _onNopButtonClicked(self):
        return
    
    def getLocalSmdaReport(self):
        local_report = self.parent.mcrit_interface.convertIdbToSmda()
        if local_report is not None:
            # some information obtained from IDA directly
            local_report.sha256 = idaapi.retrieve_input_file_sha256().hex()
            local_report.filename = self.os_path.basename(idaapi.get_root_filename())
            local_report.buffer_size = idaapi.retrieve_input_file_size()
            local_report.smda_version = "MCRIT4IDA v%s via SMDA %s" % (self.parent.config.VERSION, local_report.smda_version)
            # if yes, use information from it
            if self.parent.remote_sample_entry is not None:
                local_report.family = self.parent.remote_sample_entry.family
                local_report.version = self.parent.remote_sample_entry.version
                local_report.is_library = self.parent.remote_sample_entry.is_library
        return local_report

    def _onBuildYaraStringButtonClicked(self):
        ida_selection_start = self.cc.ida_proxy.ReadSelectionStart()
        ida_selection_end = self.cc.ida_proxy.ReadSelectionEnd()
        has_selection = (ida_selection_start is not None and ida_selection_end is not None and 
                        ida_selection_start != ida_selection_end)
        
        # fetch instruction, block, and function information based on current cursor position
        current_ea = ida_kernwin.get_screen_ea()
        current_function = self.parent.local_smda_report.findFunctionByContainedAddress(current_ea)
        current_block = self.parent.local_smda_report.findBlockByContainedAddress(current_ea)

        # for sequences of instructions, we need to emulate the procedure from SmdaFunction
        # this will allow us to correlate the individual escaped instructions with their disassembly representation
        selected_ins_sequence = []
        if has_selection:
            for smda_function in self.parent.local_smda_report.getFunctions():
                for smda_instruction in smda_function.getInstructions():
                    if smda_instruction.offset >= ida_selection_start and smda_instruction.offset < ida_selection_end:
                        selected_ins_sequence.append(smda_instruction)
            selected_ins_sequence.sort(key=lambda ins: ins.offset)
        else:
            # If no selection, use single instruction at cursor
            for smda_function in self.parent.local_smda_report.getFunctions():
                for smda_instruction in smda_function.getInstructions():
                    if smda_instruction.offset == current_ea:
                        selected_ins_sequence = [smda_instruction]
                        break
                if selected_ins_sequence:
                    break
        functions_ins_sequence = list(current_function.getInstructions()) if current_function else None
        blocks_ins_sequence = list(current_block.getInstructions()) if current_block else None

        data_bytes = b""
        if not selected_ins_sequence and has_selection:
            data_bytes = self.cc.ida_proxy.GetBytes(ida_selection_start, ida_selection_end - ida_selection_start)
        # Create and show the dialog
        dialog = self.YaraStringBuilderDialog(
            self,
            data=data_bytes,
            selection_sequence=selected_ins_sequence if selected_ins_sequence else None,
            block_sequence=blocks_ins_sequence,
            function_sequence=functions_ins_sequence,
            sha256=self.parent.local_smda_report.sha256 if self.parent.local_smda_report else "",
            offset=current_ea,
            selection_start=ida_selection_start or current_ea,
            selection_end=ida_selection_end or current_ea
        )
        dialog.exec_()

    def _onConvertSmdaButtonClicked(self):
        local_smda_report = self.getLocalSmdaReport()
        if self.parent.local_smda_report is None:
            self.parent.local_smda_report = local_smda_report
            self.parent.getRemoteSampleInformation()
        if self.parent.local_smda_report is not None:
            self.exportSmdaAction.setEnabled(True)
            self.uploadSmdaAction.setEnabled(True)
            self.buildYaraStringAction.setEnabled(True)
            # check if remote sample exists
            self.parent.mcrit_interface.querySampleSha256(self.parent.local_smda_report.sha256)
            # if yes, enable matching and use meta data
            if self.parent.remote_sample_entry is not None:
                self.getMatchResultAction.setEnabled(True)
                self.parent.local_smda_report.family = self.parent.remote_sample_entry.family
                self.parent.local_smda_report.version = self.parent.remote_sample_entry.version
                self.parent.local_smda_report.is_library = self.parent.remote_sample_entry.is_library
            # else query for family, version, library instead
            else:
                dialog = self.SmdaInfoDialog(self)
                dialog.exec_()
                smda_info = dialog.getSmdaInfo()
                self.parent.local_smda_report.family = smda_info["family"]
                self.parent.local_smda_report.version = smda_info["version"]
                self.parent.local_smda_report.is_library = smda_info["is_library"]
            self.parent.block_match_widget.enable()
            self.parent.function_match_widget.enable()
        self.parent.local_widget.update()

    def _onExportSmdaButtonClicked(self):
        # save metadata before upload to not overwrite it
        local_family = self.parent.local_smda_report.family if self.parent.local_smda_report else ""
        local_version = self.parent.local_smda_report.version if self.parent.local_smda_report else ""
        local_library = self.parent.local_smda_report.is_library if self.parent.local_smda_report else False
        # update before export, to ensure we have all most recent function label information
        self.parent.local_smda_report = self.getLocalSmdaReport()
        self.parent.local_smda_report.family = local_family
        self.parent.local_smda_report.version = local_version
        self.parent.local_smda_report.is_library = local_library
        if self.parent.local_smda_report:
            filepath = ida_kernwin.ask_file(1, self.parent.local_smda_report.filename + ".smda", 'Export SMDA report to file...')
            if filepath:
                with open(filepath, "w") as fout:
                    json.dump(self.parent.local_smda_report.toDict(), fout, indent=1, sort_keys=True)
                self.parent.local_widget.updateActivityInfo("IDB exported to: \"%s\"." % filepath)
            else:
                self.parent.local_widget.updateActivityInfo("Export aborted.")
        else:
            self.parent.local_widget.updateActivityInfo("IDB is not converted to SMDA report yet, can't export.")

    def _onUploadSmdaButtonClicked(self):
        # save metadata before upload to not overwrite it
        local_family = self.parent.local_smda_report.family if self.parent.local_smda_report else ""
        local_version = self.parent.local_smda_report.version if self.parent.local_smda_report else ""
        local_library = self.parent.local_smda_report.is_library if self.parent.local_smda_report else False
        # update before export, to ensure we have all most recent function label information
        self.parent.local_smda_report = self.getLocalSmdaReport()
        self.parent.local_smda_report.family = local_family
        self.parent.local_smda_report.version = local_version
        self.parent.local_smda_report.is_library = local_library
        if self.parent.local_smda_report:
            self.parent.mcrit_interface.uploadReport(self.parent.local_smda_report)
            # check if remote sample exists
            if self.parent.remote_sample_id is not None:
                self.getMatchResultAction.setEnabled(True)
        else:
            self.parent.local_widget.updateActivityInfo("IDB is not converted to SMDA report yet, can't upload.")

    def _onGetMatchResultButtonClicked(self):
        if self.parent.remote_sample_id is not None:
            # fetch jobs 
            jobs = self.parent.mcrit_interface.queryJobs(sample_id=self.parent.remote_sample_id)
            # check which job the user wants to use as reference
            dialog = self.ResultChooserDialog(self, job_infos=jobs)
            dialog.exec_()
            dialog_result = dialog.getResultChosen()
            # if user wants to request a new matching, schedule it via client
            if dialog_result["is_requesting_matching_job"]:
                self.parent.mcrit_interface.requestMatchingJob(self.parent.remote_sample_id, force_update=True)
            # if otherwise a job was finished and a job_id selected, fetch the data
            elif dialog_result["selected_job_id"]:
                # we already have this matching data, so we can skip and save time
                if self.parent.matching_job_id is not None and self.parent.matching_job_id == dialog_result["selected_job_id"]:
                    pass
                else:
                    self.parent.mcrit_interface.getMatchingJobById(dialog_result["selected_job_id"])
                self.tabs.setCurrentIndex(2)
                self.hideLocalWidget()
            self.parent.function_widget.update()
            if self.parent.config.OVERVIEW_FETCH_LABELS_AUTOMATICALLY:
                self.parent.function_widget.fetchLabels()
            return
        else:
            self.parent.local_widget.updateActivityInfo("No remote Sample present yet, can't request a matching or query results.")

    def hideLocalWidget(self):
        self.splitter.setSizes([0, 1])

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
