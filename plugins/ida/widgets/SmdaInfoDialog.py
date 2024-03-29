
import helpers.QtShim as QtShim
QDialog = QtShim.get_QDialog()


class SmdaInfoDialog(QDialog):

    def __init__(self, parent):
        self.cc = parent.cc
        self.cc.QDialog.__init__(self, parent)
        self._sample_family = ""
        self._sample_version = ""
        self._sample_is_library = False
        # if we already have a report, use the same meta data information to prefill fields
        if parent.parent.local_smda_report is not None:
            self._sample_family = parent.parent.local_smda_report.family
            self._sample_version = parent.parent.local_smda_report.version
            self._sample_is_library = parent.parent.local_smda_report.is_library
        # create GUI elements
        self._createInputWidget()
        self._createButtons()
        # glue everything together
        dialog_layout = self.cc.QVBoxLayout()
        dialog_layout.addWidget(self.input_widget)
        dialog_layout.addLayout(self.button_layout)
        self.setLayout(dialog_layout)
        self.setWindowTitle(self.tr("Provide additional information about the sample"))

    def _createInputWidget(self):
        self.input_widget = self.cc.QWidget()
        # the respective fields
        self.label_family = self.cc.QLabel("Family:")
        self.edit_family = self.cc.QLineEdit(self._sample_family)
        self.label_version = self.cc.QLabel("Version:")
        self.edit_version = self.cc.QLineEdit(self._sample_version)
        self._cb_is_library = self.cc.QCheckBox("Sample is a library?")
        self._cb_is_library.setChecked(self._sample_is_library)
        # arrange in layout
        grid_layout = self.cc.QGridLayout()
        grid_layout.addWidget(self.label_family, 0, 0)
        grid_layout.addWidget(self.edit_family, 0, 1)
        grid_layout.addWidget(self.label_version, 1, 0)
        grid_layout.addWidget(self.edit_version, 1, 1)
        grid_layout.addWidget(self._cb_is_library, 2, 0, 1, 2)
        self.input_widget.setLayout(grid_layout)

    def _createButtons(self):
        self.button_layout = self.cc.QHBoxLayout()
        self.ok_button = self.cc.QPushButton(self.tr("OK"))
        self.cancel_button = self.cc.QPushButton(self.tr("Cancel"))
        self.ok_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)
        self.button_layout.addStretch(1)
        self.button_layout.addWidget(self.ok_button)
        self.button_layout.addWidget(self.cancel_button)

    def accept(self):
        # display mode
        self._sample_family = self.edit_family.text()
        self._sample_version = self.edit_version.text()
        self._sample_is_library = self._cb_is_library.isChecked()
        self.done(1)

    def getSmdaInfo(self):
        return {
            "family": self._sample_family,
            "version": self._sample_version,
            "is_library": self._sample_is_library
        }
