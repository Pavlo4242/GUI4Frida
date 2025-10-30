from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QComboBox,
                           QPushButton, QLabel, QFrame, QLineEdit, QMessageBox,
                           QApplication, QDialog, QListWidget, QListWidgetItem,
                           QDialogButtonBox, QFileDialog, QTextEdit, QCheckBox,
                           QFormLayout, QGroupBox)
from PyQt5.QtWidgets import (QPushButton, QListWidget, QHBoxLayout, QVBoxLayout,
                             QLabel, QDialog, QDialogButtonBox, QFileDialog,
                             QTextEdit, QCheckBox, QFormLayout, QGroupBox)                           
from PyQt5.QtCore import pyqtSignal, Qt
from PyQt5.QtGui import QFont

import frida
import subprocess
import qtawesome as qta
import sys
from pathlib import Path
import os

# Add project root to Python path
sys.path.append(str(Path(__file__).parent.parent.parent))
from core.android_helper import AndroidHelper


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
        self.setup_ui()

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

        # --- Application selector dialog ---
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
        add_btn = QPushButton(qta.icon('fa5s.plus'), " Add Script")
        remove_btn = QPushButton(qta.icon('fa5s.trash'), " Remove")
        up_btn = QPushButton(qta.icon('fa5s.arrow-up'), "")
        down_btn = QPushButton(qta.icon('fa5s.arrow-down'), "")

        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(remove_btn)
        btn_layout.addWidget(up_btn)
        btn_layout.addWidget(down_btn)
        btn_layout.addStretch()

        # Script list
        script_list = QListWidget()
        script_list.setDragDropMode(QListWidget.InternalMove)
        script_list.setSelectionMode(QListWidget.SingleSelection)

        # Bottom: OK/Cancel
        btn_box2 = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btn_box2.accepted.connect(script_dialog.accept)
        btn_box2.rejected.connect(script_dialog.reject)

        ok_btn = btn_box2.button(QDialogButtonBox.Ok)
        ok_btn.setEnabled(False)

        # --- Functions ---
        def update_ok_button():
            ok_btn.setEnabled(script_list.count() > 0)

        def add_script():
            paths, _ = QFileDialog.getOpenFileNames(
                script_dialog, "Select Frida Scripts", "",
                "JavaScript Files (*.js);;All Files (*.*)"
            )
            for path in paths:
                # Avoid duplicates
                if path not in [script_list.item(i).data(Qt.UserRole) for i in range(script_list.count())]:
                    item = QListWidgetItem(os.path.basename(path))
                    item.setData(Qt.UserRole, path)
                    item.setToolTip(path)
                    script_list.addItem(item)
            update_ok_button()

        def remove_script():
            for item in script_list.selectedItems():
                script_list.takeItem(script_list.row(item))
            update_ok_button()

        def move_up():
            row = script_list.currentRow()
            if row > 0:
                item = script_list.takeItem(row)
                script_list.insertItem(row - 1, item)
                script_list.setCurrentRow(row - 1)

        def move_down():
            row = script_list.currentRow()
            if row < script_list.count() - 1:
                item = script_list.takeItem(row)
                script_list.insertItem(row + 1, item)
                script_list.setCurrentRow(row + 1)

        # Connect signals
        add_btn.clicked.connect(add_script)
        remove_btn.clicked.connect(remove_script)
        up_btn.clicked.connect(move_up)
        down_btn.clicked.connect(move_down)
        script_list.itemSelectionChanged.connect(
            lambda: remove_btn.setEnabled(bool(script_list.selectedItems()))
        )

        # Layout
        dlg_layout.addLayout(btn_layout)
        dlg_layout.addWidget(QLabel("Scripts will run in order (top to bottom):"))
        dlg_layout.addWidget(script_list)
        dlg_layout.addWidget(btn_box2)

        if script_dialog.exec_() != QDialog.Accepted:
            print("[DeviceSelector] Script selection cancelled.")
            return

        if script_list.count() == 0:
            QMessageBox.warning(self, "No Scripts", "Please add at least one script.")
            return

        # Extract ordered script paths
        self.script_files = [
            script_list.item(i).data(Qt.UserRole)
            for i in range(script_list.count())
        ]

        spawn_opts = getattr(self, "frida_spawn_options", "")
        self.application_selected_for_spawn.emit(
            self.current_device, app_identifier, self.script_files, spawn_opts
        )
        print("[DeviceSelector] Script accepted and signal emitted.")

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
        known_text.setFont(QFont("Consolas", 9))

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

    def cleanup(self):
        self.process_combo.clear()
        self.device_combo.clear()
        self.current_device = None
        self.process_list = []
        self.applications = []
        self.frida_spawn_options = ""