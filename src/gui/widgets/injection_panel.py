from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                           QLabel, QProgressBar, QFrame, QMessageBox, QFileDialog,
                           QTextEdit, QApplication) # Added QApplication
from PyQt5.QtCore import Qt, pyqtSignal
import qtawesome as qta
import os # Added os import

class InjectionPanel(QWidget):
    # Signals remain the same
    injection_started = pyqtSignal(str, int)  # script, pid
    # This signal wasn't really used by MainWindow, keep for consistency or future use
    injection_completed = pyqtSignal(bool, str)
    injection_stopped = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.current_pid = None
        self.current_device_id = None
        # Reference to the actual QTextEdit from ScriptEditorPanel, set by MainWindow
        self.script_editor_widget = None # THIS WILL HOLD THE REFERENCE
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 0, 5, 5) # Adjusted margins
        layout.setSpacing(8) # Added spacing

        # Status panel
        status_frame = QFrame()
        status_frame.setStyleSheet("""
            QFrame {
                background-color: #2f3136;
                border-radius: 8px;
                padding: 8px 12px; /* Adjusted padding */
            }
        """)
        status_layout = QHBoxLayout(status_frame)
        status_layout.setContentsMargins(0,0,0,0) # No internal margins for HBox

        self.status_icon = QLabel()
        self.status_icon.setPixmap(qta.icon('fa5s.circle', color='#99aab5').pixmap(14, 14)) # Slightly smaller icon
        self.status_label = QLabel("No process selected")
        self.status_label.setStyleSheet("color: #99aab5; margin-left: 5px;") # Add margin

        status_layout.addWidget(self.status_icon)
        status_layout.addWidget(self.status_label)
        status_layout.addStretch()

        # Action buttons layout
        button_layout = QHBoxLayout()
        button_layout.setSpacing(6) # Spacing between buttons

        # Load Script Button
        self.load_btn = QPushButton(qta.icon('fa5s.folder-open', color='white'), " Load")
        self.load_btn.clicked.connect(self.load_script_file)
        self.load_btn.setToolTip("Load script from .js file")
        self.load_btn.setStyleSheet("padding: 5px 10px; background-color: #5865f2; border: none; border-radius: 4px; color: white;")

        # Clear Button (Added)
        self.clear_btn = QPushButton(qta.icon('fa5s.trash-alt', color='white'), " Clear")
        self.clear_btn.clicked.connect(self.clear_script)
        self.clear_btn.setToolTip("Clear the script editor")
        self.clear_btn.setStyleSheet("padding: 5px 10px; background-color: #4f545c; border: none; border-radius: 4px; color: white;") # Greyish button

        # Inject Button (Modified name, Execute -> Inject)
        self.inject_btn = QPushButton(qta.icon('fa5s.syringe', color='white'), " Inject") # Changed icon too
        self.inject_btn.clicked.connect(self.execute_script) # Function remains execute_script
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
        button_layout.addStretch() # Add stretch before inject/stop
        button_layout.addWidget(self.inject_btn)
        button_layout.addWidget(self.stop_btn)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(6) # Make it thinner
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: none;
                background-color: #2f3136;
                border-radius: 3px; /* Match height */
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #7289da; /* Blue chunk */
                border-radius: 3px;
            }
        """)
        self.progress_bar.hide()

        # Add widgets to main layout
        layout.addWidget(status_frame)
        # Note: The actual script editor (from ScriptEditorPanel) is part of MainWindow's layout
        layout.addLayout(button_layout)
        layout.addWidget(self.progress_bar)

    def set_script_editor_widget(self, editor_widget: QTextEdit): # Added type hint
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

        # Use os.path.expanduser('~') as a potential starting directory
        #start_dir = os.path.expanduser('~')
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
        if not script_content.strip(): # Check if script is just whitespace
            QMessageBox.warning(self, "Input Error", "Script is empty! Please load or enter a script.")
            return

        if not self.current_pid or not self.current_device_id:
            QMessageBox.warning(self, "Input Error", "No process selected. Please select a device and process first.")
            return

        print(f"[InjectionPanel] Attempting to inject script into PID: {self.current_pid} on device: {self.current_device_id}")

        # Update UI to indicate injection attempt
        self.status_icon.setPixmap(qta.icon('fa5s.spinner', color='#faa61a', animation=qta.Spin(self.status_icon)).pixmap(14, 14)) # Spinning Yellow
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
             # Should ideally not happen if button state is managed correctly, but check anyway
             print("[InjectionPanel] Stop clicked but no active PID/Device known.")
             self._set_buttons_state(process_selected=False) # Reset buttons if state is inconsistent
             return

        print(f"[InjectionPanel] Attempting to stop script for PID: {self.current_pid} on device: {self.current_device_id}")
        self.status_label.setText(f"Stopping script in PID: {self.current_pid}...")
        self.status_icon.setPixmap(qta.icon('fa5s.spinner', color='#faa61a', animation=qta.Spin(self.status_icon)).pixmap(14, 14)) # Spinning Yellow
        self._set_buttons_state(stopping=True) # Disable stop, keep others disabled
        self.progress_bar.show()
        self.progress_bar.setRange(0, 0)

        self.injection_stopped.emit() # Signal MainWindow to detach/unload

    #@pyqtSlot(str, int) # Add decorator for clarity
    def set_process(self, device_id, pid):
        """Updates the selected process and device ID. Called by MainWindow."""
        # Check if pid is None or invalid before trying int()
        if pid is None:
            print("[InjectionPanel] set_process called with PID=None. Resetting state.")
            self.current_pid = None
            self.current_device_id = device_id # Still keep device ID if provided
            self.status_label.setText("No process selected" if device_id else "No device or process selected")
            self.status_icon.setPixmap(qta.icon('fa5s.circle', color='#99aab5').pixmap(14, 14)) # Grey
            self._set_buttons_state(process_selected=False)
            return

        try:
            pid_int = int(pid)
            if pid_int <= 0:
                 raise ValueError("PID must be positive.")

            self.current_pid = pid_int
            self.current_device_id = device_id
            self.status_label.setText(f"Selected PID: {self.current_pid}") # Keep it concise
            self.status_icon.setPixmap(qta.icon('fa5s.circle', color='#43b581').pixmap(14, 14)) # Green
            self._set_buttons_state(process_selected=True)
            print(f"[InjectionPanel] Process set: PID={self.current_pid}, Device={self.current_device_id}")

        except (ValueError, TypeError) as e:
            print(f"[InjectionPanel] Error setting process: Invalid PID '{pid}'. {e}")
            self.current_pid = None
            self.current_device_id = device_id
            self.status_label.setText(f"Invalid PID")
            self.status_icon.setPixmap(qta.icon('fa5s.circle', color='#f04747').pixmap(14, 14)) # Red
            self._set_buttons_state(process_selected=False)

    # --- Methods called by MainWindow for feedback ---
    def injection_succeeded(self):
        """Updates UI when injection is confirmed successful."""
        print(f"[InjectionPanel] Injection succeeded for PID {self.current_pid}")
        self.status_icon.setPixmap(qta.icon('fa5s.check-circle', color='#43b581').pixmap(14, 14)) # Green Check
        self.status_label.setText(f"Script running in PID: {self.current_pid}")
        self._set_buttons_state(script_running=True)
        self.progress_bar.hide()
        self.progress_bar.setRange(0, 1)

    def injection_failed(self, error_message="Unknown error"):
        """Updates UI when injection fails."""
        print(f"[InjectionPanel] Injection failed for PID {self.current_pid}: {error_message}")
        self.status_icon.setPixmap(qta.icon('fa5s.times-circle', color='#f04747').pixmap(14, 14)) # Red X
        status_text = f"Injection failed"
        if self.current_pid:
            status_text += f": PID {self.current_pid}"
        self.status_label.setText(status_text)
        # Re-enable inject button only if a valid process is still technically selected
        self._set_buttons_state(process_selected=bool(self.current_pid))
        self.progress_bar.hide()
        self.progress_bar.setRange(0, 1)
        # MainWindow shows the popup, no need for one here

    def injection_stopped_update(self):
        """Updates UI after stop signal processing is complete (called by MainWindow)."""
        print(f"[InjectionPanel] Injection stopped confirmation received for PID {self.current_pid}")
        # Reset state, assuming process might still be selected
        self._set_buttons_state(process_selected=bool(self.current_pid))
        self.progress_bar.hide()
        self.progress_bar.setRange(0, 1)
        # Update status based on whether a process is still selected
        if self.current_pid:
             self.status_label.setText(f"Selected PID: {self.current_pid}") # Back to selected state
             self.status_icon.setPixmap(qta.icon('fa5s.circle', color='#43b581').pixmap(14, 14)) # Green
        else:
             self.status_label.setText("No process selected") # Or if process died
             self.status_icon.setPixmap(qta.icon('fa5s.circle', color='#99aab5').pixmap(14, 14)) # Grey

    def injection_stopped_externally(self):
        """Called by MainWindow if script stops or detaches unexpectedly."""
        pid_context = f"PID {self.current_pid}" if self.current_pid else "process"
        print(f"[InjectionPanel] Script detached/stopped externally for {pid_context}")
        self.status_label.setText(f"Script detached from {pid_context}")
        self.status_icon.setPixmap(qta.icon('fa5s.exclamation-circle', color='#faa61a').pixmap(14, 14)) # Yellow Warning
        # Reset buttons to non-running state, allow injection if process still selected
        self._set_buttons_state(process_selected=bool(self.current_pid))
        self.progress_bar.hide()
        self.progress_bar.setRange(0, 1)

    def _set_buttons_state(self, process_selected=False, injecting=False, script_running=False, stopping=False):
        """Centralized method to manage button enabled/disabled states."""
        can_inject = process_selected and not injecting and not script_running and not stopping
        can_stop = script_running and not stopping
        # Allow load/clear unless actively injecting or stopping
        can_load_clear = not injecting and not stopping

        self.inject_btn.setEnabled(can_inject)
        self.stop_btn.setEnabled(can_stop)
        self.load_btn.setEnabled(can_load_clear)
        self.clear_btn.setEnabled(can_load_clear)
