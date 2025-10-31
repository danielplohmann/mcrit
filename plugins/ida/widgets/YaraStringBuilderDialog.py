import datetime
import pyperclip

import helpers.QtShim as QtShim
QDialog = QtShim.get_QDialog()


class YaraStringBuilderDialog(QDialog):

    def __init__(self, parent, data=None, selection_sequence=None, block_sequence=None, function_sequence=None,
                 sha256="", offset=0, selection_start=0, selection_end=0):
        self.cc = parent.cc
        self.cc.QDialog.__init__(self, parent)
        self.parent = parent
        
        # Store instruction sequences and escaped bytes
        self.data = data or b""
        self.selection_sequence = selection_sequence or []
        self.block_sequence = block_sequence or []
        self.function_sequence = function_sequence or []
        
        # Context information
        self.sha256 = sha256
        self.offset = offset
        self.selection_start = selection_start
        self.selection_end = selection_end
        
        # Determine if we're in data mode (no block or function available)
        self.is_data_mode = (data is not None and block_sequence is None and function_sequence is None)
        
        # Current selection for rule generation
        self.current_scope = "selection"
        self.use_wildcards = True
        
        # Create GUI elements
        self._createInputWidget()
        self._createButtons()
        
        # Layout
        dialog_layout = self.cc.QVBoxLayout()
        dialog_layout.addWidget(self.input_widget)
        dialog_layout.addLayout(self.button_layout)
        self.setLayout(dialog_layout)
        
        self.setWindowTitle(self.tr("YARA String Builder"))
        self.resize(800, 600)
        
        # Initial rule generation
        self._updateYaraRule()

    def _createInputWidget(self):
        self.input_widget = self.cc.QWidget()
        
        # Scope selection radio buttons
        self.label_scope = self.cc.QLabel("Scope:")
        self.radio_selection = self.cc.QRadioButton("Selection")
        self.radio_block = self.cc.QRadioButton("Current Block")
        self.radio_function = self.cc.QRadioButton("Current Function")
        
        # Set default selection
        self.radio_selection.setChecked(True)
        
        # Disable options in data mode or if sequences are empty
        if self.is_data_mode or not self.block_sequence:
            self.radio_block.setEnabled(False)
        if self.is_data_mode or not self.function_sequence:
            self.radio_function.setEnabled(False)
        if not self.selection_sequence:
            self.radio_selection.setEnabled(False)
            # Default to first available option
            if self.block_sequence:
                self.radio_block.setChecked(True)
                self.current_scope = "block"
            elif self.function_sequence:
                self.radio_function.setChecked(True)
                self.current_scope = "function"
        
        # Connect radio button signals
        self.radio_selection.toggled.connect(self._onScopeChanged)
        self.radio_block.toggled.connect(self._onScopeChanged)
        self.radio_function.toggled.connect(self._onScopeChanged)
        
        # Wildcards checkbox
        self.cb_wildcards = self.cc.QCheckBox("Use wildcards (show escaped version)")
        self.cb_wildcards.setChecked(self.use_wildcards)
        self.cb_wildcards.stateChanged.connect(self._onWildcardsChanged)
        
        # Disable wildcards in data mode
        if self.is_data_mode:
            self.cb_wildcards.setEnabled(False)
        
        # YARA rule text area
        self.label_yara = self.cc.QLabel("Generated YARA Rule:")
        self.text_yara = self.cc.QTextEdit()
        self.text_yara.setFont(self.cc.QFont("Courier", 9))
        self.text_yara.setReadOnly(True)
        
        # Layout
        grid_layout = self.cc.QGridLayout()
        grid_layout.addWidget(self.label_scope, 0, 0)
        grid_layout.addWidget(self.radio_selection, 0, 1)
        grid_layout.addWidget(self.radio_block, 0, 2)
        grid_layout.addWidget(self.radio_function, 0, 3)
        grid_layout.addWidget(self.cb_wildcards, 1, 0, 1, 4)
        grid_layout.addWidget(self.label_yara, 2, 0, 1, 4)
        grid_layout.addWidget(self.text_yara, 3, 0, 1, 4)
        
        self.input_widget.setLayout(grid_layout)

    def _createButtons(self):
        self.button_layout = self.cc.QHBoxLayout()
        
        # Copy buttons
        self.copy_escaped_button = self.cc.QPushButton(self.tr("Copy Escaped Bytes"))
        self.copy_yara_button = self.cc.QPushButton(self.tr("Copy YARA Rule"))
        self.ok_button = self.cc.QPushButton(self.tr("OK"))
        
        # Connect signals
        self.copy_escaped_button.clicked.connect(self._onCopyEscapedClicked)
        self.copy_yara_button.clicked.connect(self._onCopyYaraClicked)
        self.ok_button.clicked.connect(self.accept)
        
        # Layout
        self.button_layout.addWidget(self.copy_escaped_button)
        self.button_layout.addWidget(self.copy_yara_button)
        self.button_layout.addStretch(1)
        self.button_layout.addWidget(self.ok_button)

    def _onScopeChanged(self):
        """Handle scope radio button changes"""
        if self.radio_selection.isChecked():
            self.current_scope = "selection"
        elif self.radio_block.isChecked():
            self.current_scope = "block"
        elif self.radio_function.isChecked():
            self.current_scope = "function"
        self._updateYaraRule()

    def _onWildcardsChanged(self):
        """Handle wildcards checkbox change"""
        self.use_wildcards = self.cb_wildcards.isChecked()
        self._updateYaraRule()

    def _getCurrentSequenceInstructions(self):
        """Get current instruction sequence and escaped bytes based on scope"""
        if self.current_scope == "selection":
            return self.selection_sequence or []
        elif self.current_scope == "block":
            return self.block_sequence or []
        elif self.current_scope == "function":
            return self.function_sequence or []
        return []

    def _escapeInstruction(self, instruction):
        """Escape an instruction for YARA rule"""
        if not instruction:
            return b""
        # Escape the instruction bytes
        # Use escaped version with wildcards, annotated with disassembly
        from smda.intel.IntelInstructionEscaper import IntelInstructionEscaper
        from smda.common.BinaryInfo import BinaryInfo
        binary_info = BinaryInfo(b"")
        binary_info.architecture = self.parent.parent.local_smda_report.architecture
        binary_info.base_addr = self.parent.parent.local_smda_report.base_addr
        binary_info.binary_size = self.parent.parent.local_smda_report.binary_size
        escaped_bytes = instruction.getEscapedBinary(
            IntelInstructionEscaper,
            escape_intraprocedural_jumps=True,
            lower_addr=binary_info.base_addr,
            upper_addr=binary_info.base_addr + binary_info.binary_size,
        )
        return escaped_bytes
        
    def _formatHexBytes(self, instructions):
        """Format bytes as hex string for YARA rule"""
        if not instructions:
            return ""
        
        hex_string = ""
        hex_lines = []


        if self.use_wildcards:
            for instruction in instructions:
                try:
                    escaped_bytes = self._escapeInstruction(instruction)
                    # Convert escaped string to hex format
                    hex_bytes = "".join(escaped_bytes)
                    disasm = f"{instruction.mnemonic} {instruction.operands}" if hasattr(instruction, 'operands') and instruction.operands else instruction.mnemonic
                    hex_lines.append((hex_bytes, f"0x{instruction.offset:08X}: {disasm}"))
                except:
                    # Fallback to raw bytes if escaping fails
                    hex_bytes = instruction.bytes
                    disasm = f"{instruction.mnemonic} {instruction.operands}" if hasattr(instruction, 'operands') and instruction.operands else instruction.mnemonic
                    hex_lines.append((hex_bytes, f"0x{instruction.offset:08X}: {disasm}"))
        else:
            # Use raw bytes without wildcards
            for instruction in instructions:
                hex_bytes = instruction.bytes
                disasm = f"{instruction.mnemonic} {instruction.operands}" if hasattr(instruction, 'operands') and instruction.operands else instruction.mnemonic
                hex_lines.append((hex_bytes, f"0x{instruction.offset:08X}: {disasm}"))
            
        # Find the longest hex string to align comments
        if hex_lines:
            max_hex_length = max(len(hex_bytes) for hex_bytes, _ in hex_lines)
            
            # Format each line with proper alignment
            for hex_bytes, comment in hex_lines:
                if comment:
                    padding = " " * (max_hex_length - len(hex_bytes))
                    hex_string += f"          {hex_bytes}{padding} // {comment}\n"
                else:
                    hex_string += f"          {hex_bytes}\n"

        return hex_string

    def _updateYaraRule(self):
        """Update the YARA rule text area"""
        instructions = self._getCurrentSequenceInstructions()
        
        if not instructions and not self.is_data_mode:
            self.text_yara.setText("No data available for selected scope.")
            return
        
        # Determine rule details
        scope_name = self.current_scope
        scope_offset = self.offset
        
        if self.current_scope == "selection" and self.selection_start != self.selection_end:
            scope_offset = self.selection_start
        elif instructions and len(instructions) > 0:
            scope_offset = instructions[0].offset
        
        # Generate rule name
        rule_name = f"{self.sha256[:8]}_0x{scope_offset:08X}"
        
        # Generate current date
        current_date = datetime.datetime.now().strftime("%Y-%m-%d")
        
        # Format hex bytes
        hex_content = ""
        if self.is_data_mode:
            hex_bytes = " ".join([f"{byte:02X}" for byte in self.data])
            # Format into lines of 16 bytes each
            hex_lines = [hex_bytes[i:i+47] for i in range(0, len(hex_bytes), 48)]
            for line in hex_lines:
                hex_content += f"          {line}\n"
        else:
            hex_content = self._formatHexBytes(instructions)
        
        # Generate YARA rule
        yara_rule = f"""rule {rule_name} {{
    meta:
      date = "{current_date}"
      info = "Rule fragment created from {scope_name} found at offset 0x{scope_offset:08X} in file {self.sha256}."
    strings:
      $_0x{scope_offset:08X} = {{
{hex_content}      }}
    condition:
      any of them
}}"""
        
        self.text_yara.setText(yara_rule)

    def _onCopyEscapedClicked(self):
        """Copy escaped bytes to clipboard"""
        instructions = self._getCurrentSequenceInstructions()
        if self.is_data_mode:
            hex_string = self.data.hex()
        else:
            if self.use_wildcards:
                hex_string = " ".join(["".join([self._escapeInstruction(instruction)]) for instruction in instructions])
            else:
                hex_string = " ".join([instruction.bytes for instruction in instructions])
        pyperclip.copy(hex_string)
        self.parent.parent.local_widget.updateActivityInfo(f"Copied escaped bytes to clipboard: {len(hex_string)} bytes")


    def _onCopyYaraClicked(self):
        """Copy YARA rule to clipboard"""
        yara_rule = self.text_yara.toPlainText()
        if yara_rule:
            pyperclip.copy(yara_rule)
            self.parent.parent.local_widget.updateActivityInfo("YARA rule copied to clipboard")
