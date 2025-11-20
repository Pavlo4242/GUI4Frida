import frida
import subprocess
import qtawesome as qta
import sys
from pathlib import Path
import os
import time
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QComboBox,
                           QPushButton, QLabel, QFrame, QLineEdit, QMessageBox,
                           QApplication, QDialog, QListWidget, QListWidgetItem,
                           QDialogButtonBox, QFileDialog, QTextEdit, QCheckBox,
                           # MODIFICATION: Added QInputDialog for renaming and QSizePolicy
                           QFormLayout, QGroupBox, QInputDialog, QSizePolicy)
# MODIFICATION: Added QTimer for delayed selection
from PyQt5.QtCore import pyqtSignal, Qt, QTimer
from PyQt5.QtGui import QFont
from core.android_helper import AndroidHelper
# MODIFICATION: Added deque for history
from collections import deque


class DeviceSelector(QWidget):
    process_selected = pyqtSignal(str, int)  # device_id, pid
    application_selected_for_spawn = pyqtSignal(str, str, list, str)  # device, pkg, [scripts], options

    def __init__(self):
        super().__init__()
        self.current_device = None
        self.process_list = []
        self.applications = []
        self.script_files = []
        self.frida_spawn_options = ""
        self._temp_files = [] 
        # MODIFICATION: Add default script dir for saving/loading
        self.default_script_dir = os.path.join(os.getcwd(), 'frida_data', 'scripts')
        os.makedirs(self.default_script_dir, exist_ok=True) # Ensure it exists
        # MODIFICATION: Add history for recent processes
        self.recent_processes_history = deque(maxlen=5)
        # MODIFICATION: Store a reference to the spawn script list for renaming
        self.spawn_script_list = None
        self.setup_ui()


    def _get_temp_dir(self):
        """Gets the dedicated temp directory for spawned scripts."""
        temp_dir = os.path.join(os.getcwd(), 'frida_data', 'spawn_scripts')
        os.makedirs(temp_dir, exist_ok=True)
        return temp_dir

    def _save_temp_script(self, content):
        """Saves content to a temporary file and returns the path."""
        temp_dir = self._get_temp_dir()
        # Create a unique filename based on timestamp
        unique_id = int(time.time() * 1000)
        file_name = f"pasted_script_{unique_id}.js"
        file_path = os.path.join(temp_dir, file_name)
        
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            self._temp_files.append(file_path) # Add to tracking list
            print(f"[DeviceSelector] Saved temp script: {file_path}")
            return file_path
        except Exception as e:
            QMessageBox.critical(self, "Save Error", f"Failed to save temporary script: {e}")
            return None

    def show_paste_dialog(self, script_list_widget, update_ok_button_func): # -- Unchanged
        dlg = QDialog(self)
        dlg.setWindowTitle("Paste and Save Script (Temp)")
        dlg.resize(600, 400)
        layout = QVBoxLayout(dlg)

        editor = QTextEdit()
        # Get clipboard content
        clipboard = QApplication.clipboard()
        editor.setPlainText(clipboard.text())
        editor.setFont(QFont('Consolas', 10))

        layout.addWidget(QLabel("Paste your **Frida script content** below (saves to temp location):"))
        layout.addWidget(editor)

        btn_box = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        btn_box.button(QDialogButtonBox.Save).clicked.connect(lambda: self._handle_paste_save(editor.toPlainText(), script_list_widget, update_ok_button_func, dlg))
        btn_box.rejected.connect(dlg.reject)
        layout.addWidget(btn_box)

        dlg.exec_()
        
    # MODIFICATION: Added the missing _handle_paste_save method
    def _handle_paste_save(self, content, script_list_widget, update_ok_button_func, dialog):
        """Handles saving pasted content and updating the script list."""
        if not content.strip():
            QMessageBox.warning(dialog, "Empty Script", "Cannot save an empty script.")
            return

        temp_path = self._save_temp_script(content)
        if temp_path:
            # Add to list widget with a special prefix
            item = QListWidgetItem(f"[PASTED] {os.path.basename(temp_path)}")
            item.setData(Qt.UserRole, temp_path)
            item.setToolTip(temp_path)
            script_list_widget.addItem(item)
            update_ok_button_func()
            dialog.accept() # Close the dialog
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background-color: #2f3136;
                border-radius: 8px;
                padding: 10px;
            }
            QComboBox {
                background-color: #36393f;
                border: none;
                border-radius: 4px;
                padding: 8px;
                color: white;
                min-width: 200px;
            }
            QComboBox::drop-down {
                border: none;
                padding-right: 10px;
            }
        """)
        frame_layout = QVBoxLayout(frame)

        # Device selection
        device_layout = QHBoxLayout()
        self.device_combo = QComboBox()
        self.device_combo.setPlaceholderText("Select Device...")
        self.device_combo.currentIndexChanged.connect(self.on_device_changed)

        refresh_btn = QPushButton(qta.icon('fa5s.sync'), "")
        refresh_btn.setToolTip("Refresh Devices")
        refresh_btn.clicked.connect(self.refresh_devices)

        device_layout.addWidget(QLabel("Device:"))
        device_layout.addWidget(self.device_combo, 1)
        device_layout.addWidget(refresh_btn)
        frame_layout.addLayout(device_layout)

        # Process / Spawn row
        process_spawn_layout = QHBoxLayout()

        self.process_filter = QLineEdit()
        self.process_filter.setPlaceholderText("Filter running processes...")
        self.process_filter.textChanged.connect(self.filter_processes)

        self.process_combo = QComboBox()
        self.process_combo.setPlaceholderText("Attach to Process...")
        self.process_combo.currentIndexChanged.connect(self.on_process_changed)
        self.process_combo.setMaxVisibleItems(20)
        self.process_combo.setStyleSheet("QComboBox QListView { min-width: 300px; }")

        refresh_proc_btn = QPushButton(qta.icon('fa5s.sync'), "")
        refresh_proc_btn.setToolTip("Refresh Running Processes")
        refresh_proc_btn.clicked.connect(self.refresh_processes)

        self.spawn_app_btn = QPushButton(qta.icon('fa5s.rocket'), " Spawn App...")
        self.spawn_app_btn.setToolTip("Select an installed application to spawn")
        self.spawn_app_btn.clicked.connect(self.show_spawn_dialog)
        self.spawn_app_btn.setEnabled(False)
        refresh_proc_btn.clicked.connect(self.refresh_processes)

        self.frida_opts_btn = QPushButton(qta.icon('fa5s.cog'), " Frida Options")
        self.frida_opts_btn.setToolTip("Configure Frida spawn command line options")
        self.frida_opts_btn.clicked.connect(self.show_frida_options_dialog)
        self.frida_opts_btn.setEnabled(False)

        process_spawn_layout.addWidget(QLabel("Process:"))
        process_spawn_layout.addWidget(self.process_filter)
        process_spawn_layout.addWidget(self.process_combo, 1)
        process_spawn_layout.addWidget(refresh_proc_btn)
        process_spawn_layout.addWidget(self.spawn_app_btn)
        process_spawn_layout.addWidget(self.frida_opts_btn)

        frame_layout.addLayout(process_spawn_layout)
        
        # MODIFICATION: Add Recent Processes List
        recent_label = QLabel("Recent Targets:")
        recent_label.setStyleSheet("font-size: 11px; color: #96989d; margin-top: 5px;")
        frame_layout.addWidget(recent_label)
        
        self.recent_processes_list = QListWidget()
        self.recent_processes_list.setFixedHeight(100) # Keep it constrained
        self.recent_processes_list.setStyleSheet("""
            QListWidget {
                background-color: #36393f;
                border: 1px solid #202225;
                border-radius: 4px;
                padding: 4px;
            }
            QListWidget::item {
                padding: 5px;
                border-radius: 4px;
                color: #dcddde;
            }
            QListWidget::item:hover {
                background-color: #40444b;
            }
            QListWidget::item:selected {
                background-color: #5865f2;
                color: white;
            }
        """)
        self.recent_processes_list.itemClicked.connect(self._on_recent_process_clicked)
        frame_layout.addWidget(self.recent_processes_list)
        
        layout.addWidget(frame)

        self.refresh_devices()


    def refresh_devices(self):
        self.device_combo.clear()
        try:
            devices = frida.enumerate_devices()
            for device in devices:
                if device.type == 'usb':
                    self.device_combo.addItem(f"{device.name} (USB)", device.id)
        except Exception as e:
            print(f"Error enumerating devices: {e}")
        finally:
            if self.device_combo.count() > 0:
                self.device_combo.setCurrentIndex(0)

    def on_device_changed(self, index):
        if index < 0:
            self.current_device = None
            self.applications = []
            self.spawn_app_btn.setEnabled(False)
            self.frida_opts_btn.setEnabled(False)
            self.refresh_processes()
            return

        device_id = self.device_combo.currentData()
        self.current_device = device_id
        self.refresh_applications()
        self.refresh_processes()
        self.spawn_app_btn.setEnabled(True)
        self.frida_opts_btn.setEnabled(True)

    def refresh_applications(self):
        self.applications = []
        if not self.current_device:
            self.spawn_app_btn.setEnabled(False)
            return

        print(f"[DeviceSelector] Refreshing applications for {self.current_device}...")
        try:
            device = frida.get_device(self.current_device)
            if device.type != 'usb':
                print(f"[DeviceSelector] Spawning only supported for USB devices.")
                self.spawn_app_btn.setEnabled(False)
                return

            raw_apps = device.enumerate_applications()
            user_apps = []
            for app in raw_apps:
                if app.identifier and '.' in app.identifier:
                    user_apps.append({'name': app.name, 'identifier': app.identifier})

            user_apps.sort(key=lambda x: x['name'].lower())
            self.applications = user_apps
            print(f"[DeviceSelector] Found {len(self.applications)} user applications.")
            self.spawn_app_btn.setEnabled(len(self.applications) > 0)

        except frida.ServerNotRunningError:
            QMessageBox.warning(self, "Server Error", f"Frida server not running on {self.current_device}.")
            self.spawn_app_btn.setEnabled(False)
        except frida.TransportError:
            QMessageBox.warning(self, "Device Error", f"Device {self.current_device} disconnected.")
            self.spawn_app_btn.setEnabled(False)
        except Exception as e:
            print(f"[DeviceSelector] Error refreshing applications: {e}")
            self.spawn_app_btn.setEnabled(False)

    def refresh_processes(self):
        self.process_combo.clear()
        self.process_list.clear()

        if not self.current_device:
            return

        try:
            device = frida.get_device(self.current_device)
            if device.type == 'usb':
                self.process_combo.addItem("Checking device status...")
                QApplication.processEvents()

                if not AndroidHelper.is_device_connected(self.current_device):
                    raise Exception(f"Device {self.current_device} not connected")

                if not AndroidHelper.is_frida_running(self.current_device):
                    QMessageBox.warning(self, "Server Error",
                                        f"Frida server is not running on {self.current_device}.")
                    self.process_combo.clear()
                    self.process_combo.addItem("Frida server not running")
                    return

                self.process_combo.clear()
                processes = device.enumerate_processes()
                processes.sort(key=lambda p: p.name.lower() if p.name else "")
                for process in processes:
                    if process.pid > 0 and process.name:
                        self.process_list.append({'name': process.name, 'pid': process.pid})

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to refresh processes: {e}")
            self.process_combo.clear()
            self.process_combo.addItem("Error loading processes")

        self.filter_processes(self.process_filter.text())

    def filter_processes(self, text):
        search_text = text.lower()
        self.process_combo.clear()
        if not self.current_device:
            return

        items_added = 0
        for process in self.process_list:
            if search_text in process['name'].lower():
                self.process_combo.addItem(f"{process['name']} (PID: {process['pid']})", process['pid'])
                items_added += 1

        if items_added == 0 and search_text:
            self.process_combo.setPlaceholderText("No matches found")
        elif not search_text:
            self.process_combo.setPlaceholderText("Attach to Process...")

    def on_process_changed(self, index):
        if index < 0:
            return
        try:
            device_id = self.device_combo.currentData()
            pid = self.process_combo.currentData()
            if pid is None:
                return
            pid = int(pid)
            if device_id and pid > 0:
                self.process_selected.emit(device_id, pid)
                # MODIFICATION: Add to recent list on attach
                name = self.process_combo.currentText().split(' (PID:')[0].strip()
                self._add_to_recent_processes(device_id, pid, name)
        except Exception as e:
            print(f"Error in process selection: {e}")

    def show_spawn_dialog(self):
        if not self.current_device:
            QMessageBox.warning(self, "No Device", "Please select a device first.")
            return
        if not self.applications:
            QMessageBox.information(self, "No Apps", "No user applications found. Refreshing...")
            self.refresh_applications()
            if not self.applications:
                QMessageBox.warning(self, "No Apps", "Could not find any user applications to spawn.")
                return

        # --- START OF MOVED BLOCK ---
        # MODIFICATION: Application selector dialog MUST come before script dialog
        dialog = QDialog(self)
        dialog.setWindowTitle("Select Application to Spawn")
        layout = QVBoxLayout(dialog)

        filter_edit = QLineEdit()
        filter_edit.setPlaceholderText("Filter applications...")
        list_widget = QListWidget()
        list_widget.setStyleSheet("QListWidget::item { padding: 5px; }")

        def populate_list(text=""):
            list_widget.clear()
            fl = text.lower()
            for app in self.applications:
                if fl in app['name'].lower() or fl in app['identifier'].lower():
                    item = QListWidgetItem(f"{app['name']} ({app['identifier']})")
                    item.setData(Qt.UserRole, app['identifier'])
                    list_widget.addItem(item)

        filter_edit.textChanged.connect(populate_list)
        populate_list()
        list_widget.itemDoubleClicked.connect(dialog.accept)

        btn_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btn_box.accepted.connect(dialog.accept)
        btn_box.rejected.connect(dialog.reject)

        layout.addWidget(QLabel("Select an application:"))
        layout.addWidget(filter_edit)
        layout.addWidget(list_widget)
        layout.addWidget(btn_box)

        if dialog.exec_() != QDialog.Accepted:
            return

        selected = list_widget.currentItem()
        if not selected:
            return
        app_identifier = selected.data(Qt.UserRole)
        print(f"[DeviceSelector] Spawning app selected: {app_identifier}")

        # --- Script input dialog ---
        script_dialog = QDialog(self)
        script_dialog.setWindowTitle(f"Scripts for {app_identifier}")
        script_dialog.setMinimumSize(700, 500)
        dlg_layout = QVBoxLayout(script_dialog)

        # Top: Buttons
        btn_layout = QHBoxLayout()
        
        paste_btn = QPushButton(qta.icon('fa5s.clipboard', color='white'), " Paste & Save") 
        paste_btn.setToolTip("Paste script from clipboard and save as a temporary file for injection")
        
        add_btn = QPushButton(qta.icon('fa5s.plus'), " Add Script File...") 
        remove_btn = QPushButton(qta.icon('fa5s.trash'), " Remove")
        up_btn = QPushButton(qta.icon('fa5s.arrow-up'), "")
        down_btn = QPushButton(qta.icon('fa5s.arrow-down'), "")

        btn_layout.addWidget(paste_btn) 
        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(remove_btn)
        btn_layout.addWidget(up_btn)
        btn_layout.addWidget(down_btn)
        btn_layout.addStretch()

        # MODIFICATION: Initialize spawn_script_list properly
        self.spawn_script_list = QListWidget()
        self.spawn_script_list.setDragDropMode(QListWidget.InternalMove)
        self.spawn_script_list.setSelectionMode(QListWidget.SingleSelection)
        self.spawn_script_list.itemDoubleClicked.connect(self._handle_script_item_double_clicked)

        # Bottom: OK/Cancel
        btn_box2 = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btn_box2.accepted.connect(script_dialog.accept)
        btn_box2.rejected.connect(script_dialog.reject)

        ok_btn = btn_box2.button(QDialogButtonBox.Ok)
        ok_btn.setEnabled(False)

        # --- Functions ---
        def update_ok_button():
            ok_btn.setEnabled(self.spawn_script_list.count() > 0)

        def add_script():
            start_dir = self.default_script_dir
            
            paths, _ = QFileDialog.getOpenFileNames(
                script_dialog, "Select Frida Scripts", start_dir,
                "JavaScript Files (*.js);;All Files (*.*)"
            )
            for path in paths:
                if path not in [self.spawn_script_list.item(i).data(Qt.UserRole) for i in range(self.spawn_script_list.count())]:
                    item = QListWidgetItem(os.path.basename(path))
                    item.setData(Qt.UserRole, path)
                    item.setToolTip(path)
                    self.spawn_script_list.addItem(item)
            update_ok_button()

        def remove_script():
            for item in self.spawn_script_list.selectedItems():
                self.spawn_script_list.takeItem(self.spawn_script_list.row(item))
            update_ok_button()

        def move_up():
            row = self.spawn_script_list.currentRow()
            if row > 0:
                item = self.spawn_script_list.takeItem(row)
                self.spawn_script_list.insertItem(row - 1, item)
                self.spawn_script_list.setCurrentRow(row - 1)

        def move_down():
            row = self.spawn_script_list.currentRow()
            if row < self.spawn_script_list.count() - 1:
                item = self.spawn_script_list.takeItem(row)
                self.spawn_script_list.insertItem(row + 1, item)
                self.spawn_script_list.setCurrentRow(row + 1)

        # Connect signals
        paste_btn.clicked.connect(lambda: self.show_paste_dialog(self.spawn_script_list, update_ok_button)) 
        add_btn.clicked.connect(add_script)
        remove_btn.clicked.connect(remove_script)
        up_btn.clicked.connect(move_up)
        down_btn.clicked.connect(move_down)
        self.spawn_script_list.itemSelectionChanged.connect(
            lambda: remove_btn.setEnabled(bool(self.spawn_script_list.selectedItems()))
        )
        
        # Populate script list if self.script_files is already set
        for path in self.script_files:
            item_text = f"[PASTED] {os.path.basename(path)}" if path in self._temp_files else os.path.basename(path)
            item = QListWidgetItem(item_text)
            item.setData(Qt.UserRole, path)
            item.setToolTip(path)
            self.spawn_script_list.addItem(item)
        update_ok_button()

        # Layout
        dlg_layout.addLayout(btn_layout)
        dlg_layout.addWidget(QLabel("Scripts will run in order (top to bottom):"))
        dlg_layout.addWidget(self.spawn_script_list)
        dlg_layout.addWidget(btn_box2)

        if script_dialog.exec_() != QDialog.Accepted:
            print("[DeviceSelector] Script selection cancelled.")
            return

        if self.spawn_script_list.count() == 0:
            QMessageBox.warning(self, "No Scripts", "Please add at least one script.")
            return

        # Extract ordered script paths
        self.script_files = [
            self.spawn_script_list.item(i).data(Qt.UserRole)
            for i in range(self.spawn_script_list.count())
        ]
        
        # MODIFICATION: Add to recent list on spawn
        app_name = selected.text().split(' (')[0].strip()
        self._add_to_recent_processes(self.current_device, 0, app_name)

        spawn_opts = getattr(self, "frida_spawn_options", "")
        self.application_selected_for_spawn.emit(
            self.current_device, app_identifier, self.script_files, spawn_opts
        )
        print("[DeviceSelector] Script accepted and signal emitted.")
        # --- END OF MOVED BLOCK ---

    def show_frida_options_dialog(self):
        dlg = QDialog(self)
        dlg.setWindowTitle("Frida Spawn Options")
        dlg.setMinimumWidth(580)
        layout = QVBoxLayout(dlg)

        # Common switches
        common_group = QGroupBox("Common switches")
        common_layout = QVBoxLayout(common_group)
        self.pause_chk = QCheckBox("--pause   (do not resume after spawn)")
        self.debug_chk = QCheckBox("-d        (enable debugging)")
        self.device_chk = QCheckBox("-D <id>   (specify device, auto-filled)")
        self.output_chk = QCheckBox("-O <file> (write output to file)")
        self.stdio_chk = QCheckBox("--stdio  (inherit stdin/stdout)")

        for chk in (self.pause_chk, self.debug_chk, self.device_chk, self.output_chk, self.stdio_chk):
            common_layout.addWidget(chk)
        layout.addWidget(common_group)

        # Custom flags
        extra_group = QGroupBox("Custom flags (order matters)")
        extra_layout = QFormLayout(extra_group)
        self.extra1_edit = QLineEdit()
        self.extra1_edit.setPlaceholderText("e.g. --runtime=v8")
        self.extra2_edit = QLineEdit()
        self.extra2_edit.setPlaceholderText("e.g. --no-pause")
        extra_layout.addRow("Extra flag 1:", self.extra1_edit)
        extra_layout.addRow("Extra flag 2:", self.extra2_edit)
        layout.addWidget(extra_group)

        # Known flags
        known_text = QTextEdit()
        known_text.setReadOnly(True)
        known_text.setMinimumHeight(180)
        known_text.setFont(QFont("Consolas", 11))

        if not hasattr(self, "_frida_help_cache"):
            try:
                self._frida_help_cache = subprocess.check_output(
                    ["frida", "--help"], stderr=subprocess.STDOUT, text=True
                )
            except Exception as e:
                self._frida_help_cache = f"Could not run `frida --help`: {e}"
        known_text.setPlainText(self._frida_help_cache)
        layout.addWidget(QLabel("<b>Known Frida CLI flags (from `frida --help`)</b>"))
        layout.addWidget(known_text)

        # Buttons
        btn_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btn_box.accepted.connect(dlg.accept)
        btn_box.rejected.connect(dlg.reject)
        layout.addWidget(btn_box)

        # Restore previous options
        if self.frida_spawn_options:
            self._apply_options_to_widgets(self.frida_spawn_options)

        if dlg.exec_() != QDialog.Accepted:
            return

        opts = []
        if self.pause_chk.isChecked():   opts.append("--pause")
        if self.debug_chk.isChecked():   opts.append("-d")
        if self.device_chk.isChecked():  opts.append(f"-D {self.current_device}")
        if self.output_chk.isChecked():  opts.append("-O")
        if self.stdio_chk.isChecked():   opts.append("--stdio")
        if self.extra1_edit.text().strip(): opts.append(self.extra1_edit.text().strip())
        if self.extra2_edit.text().strip(): opts.append(self.extra2_edit.text().strip())

        self.frida_spawn_options = " ".join(opts)
        self.frida_opts_btn.setIcon(qta.icon('fa5s.cog'))
        self.frida_opts_btn.setText(f"Frida Options ({len(opts)})")
        print(f"[DeviceSelector] Frida spawn options set: {self.frida_spawn_options}")

        
    def _apply_options_to_widgets(self, option_str: str):
        parts = option_str.split()
        i = 0
        while i < len(parts):
            flag = parts[i]
            if flag == "--pause": self.pause_chk.setChecked(True)
            elif flag == "-d": self.debug_chk.setChecked(True)
            elif flag == "--stdio": self.stdio_chk.setChecked(True)
            elif flag.startswith("-D"): self.device_chk.setChecked(True); i += 1
            elif flag.startswith("-O"): self.output_chk.setChecked(True)
            else:
                if not self.extra1_edit.text(): self.extra1_edit.setText(flag)
                elif not self.extra2_edit.text(): self.extra2_edit.setText(flag)
            i += 1

    def get_selected_process_info(self):
        try:
            index = self.process_combo.currentIndex()
            if index >= 0:
                device_id = self.device_combo.currentData()
                pid = self.process_combo.currentData()
                name = self.process_combo.currentText().split('(')[0].strip()
                if device_id and pid:
                    return {'device_id': device_id, 'pid': pid, 'name': name}
        except Exception as e:
            print(f"Error getting process info: {e}")
        return None

    def select_device(self, device_id):
        index = self.device_combo.findData(device_id)
        if index >= 0:
            self.device_combo.setCurrentIndex(index)

    def select_process(self, pid):
        for i in range(self.process_combo.count()):
            item_data = self.process_combo.itemData(i)
            if item_data and int(item_data) == int(pid):
                self.process_combo.setCurrentIndex(i)
                break

    # MODIFICATION: New method to handle starting a rename
    def _handle_script_item_double_clicked(self, item):
        """Allows renaming a script file on double-click."""
        if not self.spawn_script_list:
            return
            
        # Only allow renaming if it's not a [PASTED] temp file
        if item.text().startswith("[PASTED]"):
            QMessageBox.information(self, "Rename Not Allowed", "Cannot rename a temporary [PASTED] script.")
            return

        old_name_full = os.path.basename(item.text())
        old_name, ext = os.path.splitext(old_name_full)

        new_name, ok = QInputDialog.getText(self, "Rename Script", 
                                            "Enter new script name (no .js):", 
                                            QLineEdit.Normal, old_name)
        
        if ok and new_name and new_name != old_name:
            self._handle_script_item_renamed(item, new_name)

    # MODIFICATION: New method to handle saving the renamed script
    def _handle_script_item_renamed(self, item, new_name_base):
        """Silently saves the script to the default script directory after renaming."""
        old_path = item.data(Qt.UserRole)
        
        new_name = new_name_base.strip()
        if not new_name.endswith('.js'):
            new_name += '.js'
        
        try:
            new_path = os.path.join(self.default_script_dir, new_name)
            
            if old_path == new_path:
                item.setText(new_name)
                return # No change
                
            # Read old content
            with open(old_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Write new content
            with open(new_path, 'w', encoding='utf-8') as f:
                f.write(content)
                
            # Update item's data to point to new file
            item.setText(new_name)
            item.setData(Qt.UserRole, new_path)
            item.setToolTip(new_path)
            
            print(f"[DeviceSelector] Renamed/copied script saved to: {new_path}")
            
            # We no longer remove the old script, this acts as "Save As"
            # If the old file was also in the default script dir, remove it
            # old_dir = os.path.dirname(old_path)
            # if old_dir == self.default_script_dir and old_path != new_path:
            #     os.remove(old_path)
                
        except Exception as e:
            QMessageBox.critical(self, "Rename Error", f"Could not save renamed script: {e}")
            # Revert text
            item.setText(os.path.basename(old_path))

    # MODIFICATION: New method to add to recent processes
    def _add_to_recent_processes(self, device_id, pid, name):
        """Adds a process to the recent history deque and updates the UI list."""
        try:
            entry = {"device_id": device_id, "pid": int(pid), "name": name}
        except (ValueError, TypeError):
            return # Invalid data

        # Remove duplicates before adding
        new_history = deque(maxlen=5)
        is_duplicate = False
        for e in self.recent_processes_history:
            if e["device_id"] == entry["device_id"] and e["name"] == entry["name"] and e["pid"] == entry["pid"]:
                 is_duplicate = True
            if e != entry:
                new_history.append(e)
        
        new_history.appendleft(entry)
        self.recent_processes_history = new_history
        
        self._update_recent_processes_list()

    # MODIFICATION: New method to update the recent processes UI list
    def _update_recent_processes_list(self):
        """Clears and repopulates the recent processes QListWidget."""
        self.recent_processes_list.clear()
        
        # Use a set to avoid showing the same name/pid combo twice if it's in history multiple times
        seen = set()
        for entry in self.recent_processes_history:
            entry_key = (entry['device_id'], entry['name'], entry['pid'])
            if entry_key in seen:
                continue
            seen.add(entry_key)

            pid_str = f"PID: {entry['pid']}" if entry['pid'] > 0 else "SPAWN"
            item = QListWidgetItem(f"{entry['name']} ({pid_str})")
            item.setData(Qt.UserRole, entry)
            item.setToolTip(f"Click to select {entry['name']} on {entry['device_id']}")
            self.recent_processes_list.addItem(item)
            
    # MODIFICATION: New method to handle clicking on a recent process
    def _on_recent_process_clicked(self, item):
        """Selects a device and process from the recent list."""
        entry = item.data(Qt.UserRole)
        if not entry:
            return
            
        self.select_device(entry['device_id'])
        
        if entry['pid'] > 0:
            # We need to wait for the device change to propagate and processes to refresh
            # A timer is a simple way to do this.
            QTimer.singleShot(250, lambda: self.select_process(entry['pid']))
        else:
            # It's a spawn target, just select the device
            self.process_combo.setCurrentIndex(-1) # Clear process selection


    def cleanup(self):
        """Clean up state and remove temporary files."""
        self.process_combo.clear()
        self.device_combo.clear()
        self.current_device = None
        self.process_list = []
        self.applications = []
        self.frida_spawn_options = ""

        # MODIFIED: Cleanup temporary files
        print("[DeviceSelector] Cleaning up temporary spawn scripts...")
        for file_path in getattr(self, '_temp_files', []):
            try:
                # Only attempt to remove files created by this instance in its session
                if os.path.exists(file_path):
                    os.remove(file_path)
                    print(f"  Removed: {file_path}")
            except Exception as e:
                print(f"  Failed to remove {file_path}: {e}")
        self._temp_files = []