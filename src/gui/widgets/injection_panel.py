from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                           QLabel, QProgressBar, QFrame, QMessageBox, QFileDialog,
                           QTextEdit, QApplication, QLineEdit) # MODIFICATION: Added QLineEdit
from PyQt5.QtCore import Qt, pyqtSignal
import qtawesome as qta
import os 

class InjectionPanel(QWidget):
    # Signals remain the same
    injection_started = pyqtSignal(str, int)  # script, pid
    injection_completed = pyqtSignal(bool, str)
    injection_stopped = pyqtSignal()
    
    # MODIFICATION: New signal for posting REPL messages
    message_posted = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.current_pid = None
        self.current_device_id = None
        # Reference to the actual QTextEdit from ScriptEditorPanel, set by MainWindow
        self.script_editor_widget = None # THIS WILL HOLD THE REFERENCE
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 0, 5, 5) 
        layout.setSpacing(8) 

        # Status panel
        status_frame = QFrame()
        status_frame.setStyleSheet("""
            QFrame {
                background-color: #2f3136;
                border-radius: 8px;
                padding: 8px 12px;
            }
        """)
        status_layout = QHBoxLayout(status_frame)
        status_layout.setContentsMargins(0,0,0,0) 

        self.status_icon = QLabel()
        self.status_icon.setPixmap(qta.icon('fa5s.circle', color='#99aab5').pixmap(14, 14)) 
        self.status_label = QLabel("No process selected")
        self.status_label.setStyleSheet("color: #99aab5; margin-left: 5px;") 

        status_layout.addWidget(self.status_icon)
        status_layout.addWidget(self.status_label)
        status_layout.addStretch()

        # Action buttons layout
        button_layout = QHBoxLayout()
        button_layout.setSpacing(6) 

        # Load Script Button
        self.load_btn = QPushButton(qta.icon('fa5s.folder-open', color='white'), " Load")
        self.load_btn.clicked.connect(self.load_script_file)
        self.load_btn.setToolTip("Load script from .js file")
        self.load_btn.setStyleSheet("padding: 5px 10px; background-color: #5865f2; border: none; border-radius: 4px; color: white;")

        # Clear Button (Added)
        self.clear_btn = QPushButton(qta.icon('fa5s.trash-alt', color='white'), " Clear")
        self.clear_btn.clicked.connect(self.clear_script)
        self.clear_btn.setToolTip("Clear the script editor")
        self.clear_btn.setStyleSheet("padding: 5px 10px; background-color: #4f545c; border: none; border-radius: 4px; color: white;") 

        # Inject Button (Modified name, Execute -> Inject)
        self.inject_btn = QPushButton(qta.icon('fa5s.syringe', color='white'), " Inject") 
        self.inject_btn.clicked.connect(self.execute_script) 
        self.inject_btn.setToolTip("Inject the current script into the selected process")
        self.inject_btn.setEnabled(False) # Disable initially
        self.inject_btn.setStyleSheet("""
            QPushButton { background-color: #43b581; color: white; padding: 5px 10px; border: none; border-radius: 4px; font-weight: bold; }
            QPushButton:hover { background-color: #3ca374; }
            QPushButton:disabled { background-color: #2f3136; color: #72767d; }
        """)

        # Stop Button
        self.stop_btn = QPushButton(qta.icon('fa5s.stop', color='white'), " Stop")
        self.stop_btn.clicked.connect(self.stop_injection)
        self.stop_btn.setToolTip("Stop the currently injected script")
        self.stop_btn.setEnabled(False) # Disable initially
        self.stop_btn.setStyleSheet("""
            QPushButton { background-color: #f04747; color: white; padding: 5px 10px; border: none; border-radius: 4px; font-weight: bold; }
            QPushButton:hover { background-color: #d84040; }
            QPushButton:disabled { background-color: #2f3136; color: #72767d; }
        """)

        button_layout.addWidget(self.load_btn)
        button_layout.addWidget(self.clear_btn)
        button_layout.addStretch() 
        button_layout.addWidget(self.inject_btn)
        button_layout.addWidget(self.stop_btn)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(6) 
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: none;
                background-color: #2f3136;
                border-radius: 3px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #7289da;
                border-radius: 3px;
            }
        """)
        self.progress_bar.hide()
        
        # MODIFICATION: Add REPL input layout
        repl_layout = QHBoxLayout()
        repl_layout.setSpacing(6)
        
        self.command_input = QLineEdit()
        self.command_input.setPlaceholderText("Send message to script (e.g., 'COMMAND_NAME') and press Enter...")
        self.command_input.setStyleSheet("padding: 5px;")
        self.command_input.returnPressed.connect(self.post_message_to_script)
        
        self.send_btn = QPushButton(qta.icon('fa5s.paper-plane', color='white'), " Send")
        self.send_btn.clicked.connect(self.post_message_to_script)
        self.send_btn.setStyleSheet("padding: 5px 10px; background-color: #5865f2; border: none; border-radius: 4px; color: white;")
        
        repl_layout.addWidget(self.command_input)
        repl_layout.addWidget(self.send_btn)
        
        # MODIFICATION: REPL starts disabled
        self.command_input.setEnabled(False)
        self.send_btn.setEnabled(False)


        # Add widgets to main layout
        layout.addWidget(status_frame)
        layout.addLayout(button_layout)
        # MODIFICATION: Add the new REPL layout
        layout.addLayout(repl_layout)
        layout.addWidget(self.progress_bar)

    def set_script_editor_widget(self, editor_widget: QTextEdit): 
        """Sets the reference to the QTextEdit widget from ScriptEditorPanel."""
        self.script_editor_widget = editor_widget
        print("[InjectionPanel] Script editor widget reference set.")

    def clear_script(self):
        """Clears the script editor content."""
        if self.script_editor_widget:
            self.script_editor_widget.clear()
            print("[InjectionPanel] Script editor cleared.")
        else:
            print("[InjectionPanel] Error: Script editor reference not set.")
            QMessageBox.warning(self, "Internal Error", "Script editor reference not found.")

    def load_script_file(self):
        """Loads script content from a file into the editor."""
        if not self.script_editor_widget:
            QMessageBox.critical(self, "Internal Error", "Script editor reference not set.")
            return

        start_dir = os.getcwd()
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            "Load Frida Script",
            start_dir,
            "JavaScript Files (*.js);;All Files (*.*)"
        )

        if file_name:
            try:
                # Use UTF-8 encoding for broader compatibility
                with open(file_name, 'r', encoding='utf-8') as f:
                    script_content = f.read()
                self.script_editor_widget.setPlainText(script_content)
                self.status_label.setText(f"Loaded: {os.path.basename(file_name)}")
                self.status_icon.setPixmap(qta.icon('fa5s.circle', color='#99aab5').pixmap(14, 14)) # Grey
                print(f"[InjectionPanel] Loaded script: {file_name}")
            except Exception as e:
                error_msg = f"Failed to load script: {str(e)}"
                print(f"[InjectionPanel] {error_msg}")
                QMessageBox.critical(self, "File Load Error", error_msg)

    def execute_script(self):
        """Validates and emits signal to start script injection."""
        if not self.script_editor_widget:
             QMessageBox.critical(self, "Internal Error", "Script editor reference not set.")
             return

        script_content = self.script_editor_widget.toPlainText()
        if not script_content.strip(): 
            QMessageBox.warning(self, "Input Error", "Script is empty! Please load or enter a script.")
            return

        if not self.current_pid or not self.current_device_id:
            QMessageBox.warning(self, "Input Error", "No process selected. Please select a device and process first.")
            return

        print(f"[InjectionPanel] Attempting to inject script into PID: {self.current_pid} on device: {self.current_device_id}")

        # Update UI to indicate injection attempt
        self.status_icon.setPixmap(qta.icon('fa5s.spinner', color='#faa61a', animation=qta.Spin(self.status_icon)).pixmap(14, 14)) 
        self.status_label.setText(f"Injecting into PID: {self.current_pid}...")
        self._set_buttons_state(injecting=True)
        self.progress_bar.show()
        self.progress_bar.setRange(0, 0) # Indeterminate

        try:
            # Emit the signal for MainWindow to handle the actual Frida logic
            self.injection_started.emit(script_content, self.current_pid)
        except Exception as e:
            # Handle potential errors during signal emission itself (less likely)
            error_msg = f"Internal error starting injection process: {str(e)}"
            print(f"[InjectionPanel] {error_msg}")
            self.injection_failed(error_msg) # Update UI to failed state

    def stop_injection(self):
        """Emits signal to stop the current script."""
        if not self.current_pid or not self.current_device_id:
             print("[InjectionPanel] Stop clicked but no active PID/Device known.")
             self._set_buttons_state(process_selected=False) 
             return

        print(f"[InjectionPanel] Attempting to stop script for PID: {self.current_pid} on device: {self.current_device_id}")
        self.status_label.setText(f"Stopping script in PID: {self.current_pid}...")
        self.status_icon.setPixmap(qta.icon('fa5s.spinner', color='#faa61a', animation=qta.Spin(self.status_icon)).pixmap(14, 14)) 
        self._set_buttons_state(stopping=True) 
        self.progress_bar.show()
        self.progress_bar.setRange(0, 0)

        self.injection_stopped.emit() 
        
    # MODIFICATION: New function to handle REPL input
    def post_message_to_script(self):
        """Gets text from command input and emits message_posted signal."""
        text = self.command_input.text()
        if not text.strip():
            return # Do nothing if input is empty
            
        if self.send_btn.isEnabled():
            self.message_posted.emit(text)
            self.command_input.clear()

    def set_process(self, device_id, pid):
        """Updates the selected process and device ID. Called by MainWindow."""
        if pid is None:
            print("[InjectionPanel] set_process called with PID=None. Resetting state.")
            self.current_pid = None
            self.current_device_id = device_id 
            self.status_label.setText("No process selected" if device_id else "No device or process selected")
            self.status_icon.setPixmap(qta.icon('fa5s.circle', color='#99aab5').pixmap(14, 14)) 
            self._set_buttons_state(process_selected=False)
            return

        try:
            pid_int = int(pid)
            if pid_int <= 0:
                 raise ValueError("PID must be positive.")

            self.current_pid = pid_int
            self.current_device_id = device_id
            self.status_label.setText(f"Selected PID: {self.current_pid}") 
            self.status_icon.setPixmap(qta.icon('fa5s.circle', color='#43b581').pixmap(14, 14)) 
            self._set_buttons_state(process_selected=True)
            print(f"[InjectionPanel] Process set: PID={self.current_pid}, Device={self.current_device_id}")

        except (ValueError, TypeError) as e:
            print(f"[InjectionPanel] Error setting process: Invalid PID '{pid}'. {e}")
            self.current_pid = None
            self.current_device_id = device_id
            self.status_label.setText(f"Invalid PID")
            self.status_icon.setPixmap(qta.icon('fa5s.circle', color='#f04747').pixmap(14, 14)) 
            self._set_buttons_state(process_selected=False)

    # --- Methods called by MainWindow for feedback ---
    def injection_succeeded(self):
        """Updates UI when injection is confirmed successful."""
        print(f"[InjectionPanel] Injection succeeded for PID {self.current_pid}")
        self.status_icon.setPixmap(qta.icon('fa5s.check-circle', color='#43b581').pixmap(14, 14)) 
        self.status_label.setText(f"Script running in PID: {self.current_pid}")
        self._set_buttons_state(script_running=True)
        self.progress_bar.hide()
        self.progress_bar.setRange(0, 1)

    def injection_failed(self, error_message="Unknown error"):
        """Updates UI when injection fails."""
        print(f"[InjectionPanel] Injection failed for PID {self.current_pid}: {error_message}")
        self.status_icon.setPixmap(qta.icon('fa5s.times-circle', color='#f04747').pixmap(14, 14)) 
        status_text = f"Injection failed"
        if self.current_pid:
            status_text += f": PID {self.current_pid}"
        self.status_label.setText(status_text)
        self._set_buttons_state(process_selected=bool(self.current_pid))
        self.progress_bar.hide()
        self.progress_bar.setRange(0, 1)

    def injection_stopped_update(self):
        """Updates UI after stop signal processing is complete (called by MainWindow)."""
        print(f"[InjectionPanel] Injection stopped confirmation received for PID {self.current_pid}")
        self._set_buttons_state(process_selected=bool(self.current_pid))
        self.progress_bar.hide()
        self.progress_bar.setRange(0, 1)
        if self.current_pid:
             self.status_label.setText(f"Selected PID: {self.current_pid}") 
             self.status_icon.setPixmap(qta.icon('fa5s.circle', color='#43b581').pixmap(14, 14)) 
        else:
             self.status_label.setText("No process selected") 
             self.status_icon.setPixmap(qta.icon('fa5s.circle', color='#99aab5').pixmap(14, 14)) 

    def injection_stopped_externally(self):
        """Called by MainWindow if script stops or detaches unexpectedly."""
        pid_context = f"PID {self.current_pid}" if self.current_pid else "process"
        print(f"[InjectionPanel] Script detached/stopped externally for {pid_context}")
        self.status_label.setText(f"Script detached from {pid_context}")
        self.status_icon.setPixmap(qta.icon('fa5s.exclamation-circle', color='#faa61a').pixmap(14, 14)) 
        self._set_buttons_state(process_selected=bool(self.current_pid))
        self.progress_bar.hide()
        self.progress_bar.setRange(0, 1)

    # MODIFICATION: Updated to control the new REPL widgets
    def _set_buttons_state(self, process_selected=False, injecting=False, script_running=False, stopping=False):
        """Centralized method to manage button enabled/disabled states."""
        can_inject = process_selected and not injecting and not script_running and not stopping
        can_stop = script_running and not stopping
        can_load_clear = not injecting and not stopping
        # MODIFICATION: Can only send messages when a script is running
        can_send_message = script_running and not stopping

        self.inject_btn.setEnabled(can_inject)
        self.stop_btn.setEnabled(can_stop)
        self.load_btn.setEnabled(can_load_clear)
        self.clear_btn.setEnabled(can_load_clear)
        
        # MODIFICATION: Enable/disable REPL
        self.command_input.setEnabled(can_send_message)
        self.send_btn.setEnabled(can_send_message)