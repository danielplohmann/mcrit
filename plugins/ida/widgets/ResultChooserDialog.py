
import helpers.QtShim as QtShim
from widgets.NumberQTableWidgetItem import NumberQTableWidgetItem
QDialog = QtShim.get_QDialog()
QStyledItemDelegate = QtShim.get_QStyledItemDelegate()
QColor = QtShim.get_QColor()
QPalette = QtShim.get_QPalette()


class StatusRowDelegate(QStyledItemDelegate):
    def __init__(self, queued_rows, progress_rows, finished_rows):
        super().__init__()
        self.queued_rows = queued_rows
        self.progress_rows = progress_rows
        self.finished_rows = finished_rows

    def paint_rect(self, painter, option, index, r, g, b):
            painter.save()
            palette = option.palette
            bg_color = QColor(r, g, b)
            palette.setColor(QPalette.Base, bg_color)
            painter.setPen(QColor(0, 0, 0))  # Set text color to black explicitly
            painter.fillRect(option.rect, bg_color)
            painter.drawText(option.rect, option.displayAlignment, index.data())
            painter.restore()

    def paint(self, painter, option, index):
        if index.row() in self.queued_rows:
            self.paint_rect(painter, option, index, 200, 50, 50)
        elif index.row() in self.progress_rows:
            self.paint_rect(painter, option, index, 200, 200, 50)
        elif index.row() in self.finished_rows:
            self.paint_rect(painter, option, index, 50, 200, 50)
        else:
            # Default painting for other rows
            super().paint(painter, option, index)



class ResultChooserDialog(QDialog):

    def __init__(self, parent, job_infos):
        self.cc = parent.cc
        self.cc.QDialog.__init__(self, parent)
        self.NumberQTableWidgetItem = NumberQTableWidgetItem
        self._QtShim = QtShim
        self.job_infos = job_infos
        # create GUI elements
        self._createInputWidget()
        self._createButtons()
        # glue everything together
        dialog_layout = self.cc.QVBoxLayout()
        dialog_layout.addWidget(self.input_widget)
        dialog_layout.addLayout(self.button_layout)
        self.setLayout(dialog_layout)
        self.setWindowTitle(self.tr("Remote Match Results"))
        self._sample_family = ""
        self._sample_version = ""
        self._sample_is_library = False
        self._is_requesting_matching_job = False
        self._selected_job_id = None

    def _createInputWidget(self):
        self.input_widget = self.cc.QWidget()
        input_layout = self.cc.QVBoxLayout()
        if self.job_infos:
            self.table_jobs = self.cc.QTableWidget()
            self.table_jobs.doubleClicked.connect(self._onTableJobRowDoubleClicked)
            self.populateJobsTable()
            # arrange in layout
            input_layout.addWidget(self.table_jobs)
            self.resize(self.table_jobs.width(), self.table_jobs.height())
        else:
            self.label_no_jobs = self.cc.QLabel("No Matching Results available yet.")
            input_layout.addWidget(self.label_no_jobs)
        self.input_widget.setLayout(input_layout)

    def populateJobsTable(self):
        """
        Populate the job table
        """
        self.table_jobs.setSortingEnabled(False)
        self.table_jobs_header_labels = ["ID", "Type", "Date", "Progress"]
        self.table_jobs.clear()
        self.table_jobs.setColumnCount(len(self.table_jobs_header_labels))
        self.table_jobs.setHorizontalHeaderLabels(self.table_jobs_header_labels)
        # Identify number of table entries and prepare addresses to display
        self.table_jobs.setRowCount(len(self.job_infos))
        self.table_jobs.resizeRowToContents(0)

        row = 0
        preselected = None
        finished_rows = []
        progress_rows = []
        queued_rows = []
        for job_info in self.job_infos:
            for column, column_name in enumerate(self.table_jobs_header_labels):
                tmp_item = None
                if column == 0:
                    tmp_item = self.NumberQTableWidgetItem("%d" % job_info.number)
                elif column == 1:
                    tmp_item = self.cc.QTableWidgetItem(job_info.parameters)
                elif column == 2:
                    date_str = "Not started yet."
                    if job_info.started_at == None:
                        queued_rows.append(row)
                    elif job_info.finished_at != None:
                        date_str = job_info.finished_at[:19]
                        finished_rows.append(row)
                    elif job_info.started_at != None:
                        date_str = job_info.started_at[:19]
                        progress_rows.append(row)
                    tmp_item = self.cc.QTableWidgetItem(date_str)
                elif column == 3:
                    progress_value = 0
                    if job_info.started_at != None:
                        progress_value = 100 * job_info.progress
                        if progress_value == 100 and preselected is None:
                            preselected = row
                    tmp_item = self.NumberQTableWidgetItem("%5.2f" % progress_value)
                tmp_item.setFlags(tmp_item.flags() & ~self.cc.QtCore.Qt.ItemIsEditable)
                self.table_jobs.setItem(row, column, tmp_item)
            row += 1

        delegate = StatusRowDelegate(queued_rows, progress_rows, finished_rows)
        self.table_jobs.setItemDelegate(delegate)
        if preselected:
            self.table_jobs.setCurrentCell(preselected, 0)
        self.table_jobs.setSelectionMode(self.cc.QAbstractItemView.SingleSelection)
        self.table_jobs.resizeColumnsToContents()
        self.table_jobs.setSortingEnabled(True)
        header_view = self._QtShim.get_QHeaderView()
        header = self.table_jobs.horizontalHeader()
        header.setStretchLastSection(True)

    def _createButtons(self):
        self.button_layout = self.cc.QHBoxLayout()
        self.button_layout.addStretch(1)
        if self.job_infos:
            self.select_button = self.cc.QPushButton(self.tr("Select Result"))
            self.select_button.clicked.connect(self.accept_select)
            self.button_layout.addWidget(self.select_button)
        self.create_button = self.cc.QPushButton(self.tr("Create New Matching Job"))
        self.create_button.clicked.connect(self.accept_create)
        self.button_layout.addWidget(self.create_button)
        self.cancel_button = self.cc.QPushButton(self.tr("Cancel"))
        self.cancel_button.clicked.connect(self.reject)
        self.button_layout.addWidget(self.cancel_button)

    def _onTableJobRowDoubleClicked(self, mi):
        """
        Use the row with that was double clicked to directly select the job
        """
        selected_row = mi.row()
        if self.job_infos[selected_row].finished_at is not None and self.job_infos[selected_row].progress == 1:
            self._selected_job_id = self.job_infos[selected_row].job_id
            self.done(1)

    def accept_select(self):
        if self.job_infos:
            self._selected_job_id = None
            # fetch the row from the table
            if self.table_jobs.selectedItems():
                selected_row = self.table_jobs.selectedItems()[0].row()
                if self.job_infos[selected_row].finished_at is not None and self.job_infos[selected_row].progress == 1:
                    self._selected_job_id = self.job_infos[selected_row].job_id
                    self.done(1)

    def accept_create(self):
            self._is_requesting_matching_job = True
            self.done(1)

    def getResultChosen(self):
        return {
            "selected_job_id": self._selected_job_id,
            "is_requesting_matching_job": self._is_requesting_matching_job
        }
