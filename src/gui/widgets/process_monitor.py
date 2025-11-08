from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                           QLabel, QLineEdit, QTableWidget, QTableWidgetItem,
                           QMenu, QAction, QComboBox, QCheckBox, QFrame,
                           QHeaderView, QStyle, QStyledItemDelegate, QToolButton, QMessageBox)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer, QSize
from PyQt5.QtGui import QColor, QFont, QIcon
from PyQt5.QtCore import QThread, QObject, pyqtSignal
import frida
import re
import qtawesome as qta
from datetime import datetime
import subprocess


class KillProcessWorker(QObject):
    finished = pyqtSignal(str, str) # Signals success: pid, name
    error = pyqtSignal(str)         # Signals error message

    def __init__(self, device_id, pid, name, parent=None):
        super().__init__(parent)
        self._device_id = device_id
        self._pid = pid
        self._name = name

    def run(self):
        try:
            subprocess.run(
                ['adb', '-s', self._device_id, 'shell', 'am', 'force-stop', self._name],
                check=True,
                capture_output=True,
                text=True,
                # Add isolation and resource limits if possible (timeout is best)
                # Adding a timeout is crucial to prevent indefinite blocking
                timeout=10 
            )
            self.finished.emit(self._pid, self._name)
        except subprocess.CalledProcessError as e:
            # Handle non-zero exit code specifically
            self.error.emit(f"Command failed (Code: {e.returncode}): {e.stderr}")
        except subprocess.TimeoutExpired:
            # Handle command timing out
            self.error.emit("Process kill command timed out.")
        except Exception as e:
            # Crucial: Catch all other exceptions (e.g., adb disconnect)
            self.error.emit(f"Unhandled kill error: {type(e).__name__} - {str(e)}")

class ProcessInfoDelegate(QStyledItemDelegate):
    def paint(self, painter, option, index):
        if index.column() in [2, 3]:  # CPU and Memory columns
            value_str = index.data().replace('%', '').replace('MB', '').strip()
            if value_str and value_str != 'N/A':
                try:
                    value = float(value_str)
                    if value > 80:
                        option.backgroundBrush = QColor('#f04747')
                    elif value > 50:
                        option.backgroundBrush = QColor('#faa61a')
                except ValueError:
                    pass
        super().paint(painter, option, index)

class ProcessMonitor(QWidget):
    def __init__(self, main_window=None):
        QWidget.__init__(self)
        self.processes = []
        self.current_device = None
        self.main_window = main_window
        self.setup_ui()
        self.start_monitoring()

    def start_monitoring(self):
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.refresh_processes)
        self.update_timer.start(3000)  # Update every 3 seconds

    def stop_monitoring(self):
        if hasattr(self, 'update_timer'):
            self.update_timer.stop()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        # Device selection
        device_frame = QFrame()
        device_frame.setStyleSheet("""
            QFrame {
                background-color: #2f3136;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        device_layout = QHBoxLayout(device_frame)

        self.device_combo = QComboBox()
        self.device_combo.currentIndexChanged.connect(self.on_device_changed)

        refresh_devices_btn = QPushButton(qta.icon('fa5s.sync'), "Refresh Devices")
        refresh_devices_btn.clicked.connect(self.refresh_devices)

        device_layout.addWidget(QLabel("Device:"))
        device_layout.addWidget(self.device_combo)
        device_layout.addWidget(refresh_devices_btn)

        # Search and Filter Bar
        filter_frame = QFrame()
        filter_frame.setStyleSheet("""
            QFrame {
                background-color: #2f3136;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        filter_layout = QHBoxLayout(filter_frame)

        # Process search with regex toggle
        search_container = QFrame()
        search_layout = QHBoxLayout(search_container)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍 Filter processes (supports regex)")
        self.search_input.textChanged.connect(self.apply_filters)

        self.regex_check = QCheckBox("Regex")
        self.regex_check.toggled.connect(self.apply_filters)

        search_layout.addWidget(self.search_input)
        search_layout.addWidget(self.regex_check)

        # Advanced filters
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(['All', 'User Apps', 'System', 'Running', 'Debuggable'])
        self.filter_combo.currentTextChanged.connect(self.apply_filters)

        filter_layout.addWidget(search_container)
        filter_layout.addWidget(self.filter_combo)

        # Process Table
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(6)
        self.process_table.setHorizontalHeaderLabels([
            "PID", "Name", "Package", "User", "Status", "Debuggable"
        ])

        # Set column widths
        header = self.process_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)  # PID
        header.setSectionResizeMode(1, QHeaderView.Stretch)  # Name
        header.setSectionResizeMode(2, QHeaderView.Stretch)  # Package
        header.setSectionResizeMode(3, QHeaderView.Fixed)  # User
        header.setSectionResizeMode(4, QHeaderView.Fixed)  # Status
        header.setSectionResizeMode(5, QHeaderView.Fixed)  # Debuggable

        self.process_table.setColumnWidth(0, 80)
        self.process_table.setColumnWidth(3, 100)
        self.process_table.setColumnWidth(4, 100)
        self.process_table.setColumnWidth(5, 100)

        # Enable sorting
        self.process_table.setSortingEnabled(True)

        # Context menu
        self.process_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.process_table.customContextMenuRequested.connect(self.show_context_menu)

        # Action buttons
        action_layout = QHBoxLayout()

        self.refresh_btn = QPushButton(qta.icon('fa5s.sync'), "Refresh")
        self.refresh_btn.clicked.connect(self.refresh_processes)

        self.kill_btn = QPushButton(qta.icon('fa5s.stop'), "Kill Process")
        self.kill_btn.clicked.connect(self.kill_selected_process)

        self.inject_btn = QPushButton(qta.icon('fa5s.syringe'), "Open in Injector")
        self.inject_btn.clicked.connect(self.open_in_injector_clicked)

        self.dump_btn = QPushButton(qta.icon('fa5s.download'), "Dump APK")
        self.dump_btn.clicked.connect(self.dump_apk)

        action_layout.addWidget(self.refresh_btn)
        action_layout.addWidget(self.kill_btn)
        action_layout.addWidget(self.inject_btn)
        action_layout.addWidget(self.dump_btn)
        action_layout.addStretch()

        # Status bar
        status_bar = QFrame()
        status_bar.setStyleSheet("""
            QFrame {
                background-color: #2f3136;
                border-radius: 4px;
                padding: 5px;
            }
        """)
        status_layout = QHBoxLayout(status_bar)

        self.process_count = QLabel("0 processes")
        self.status_label = QLabel("Ready")

        status_layout.addWidget(self.process_count)
        status_layout.addStretch()
        status_layout.addWidget(self.status_label)

        # Add all components
        layout.addWidget(device_frame)
        layout.addWidget(filter_frame)
        layout.addWidget(self.process_table)
        layout.addLayout(action_layout)
        layout.addWidget(status_bar)

        # Initial device scan
        self.refresh_devices()

    def refresh_devices(self):
        self.device_combo.clear()
        try:
            devices = frida.enumerate_devices()
            for device in devices:
                if device.type == 'usb':
                    self.device_combo.addItem(f"📱 {device.name} (USB)", device.id)
        except Exception as e:
            print(f"Error enumerating devices: {e}")

    def on_device_changed(self, index):
        # Check the widget's current index directly, as the 'index'
        # argument is causing a TypeError (str vs int).
        if self.device_combo.currentIndex() >= 0:
            self.current_device = self.device_combo.currentData()
            self.refresh_processes()
            

    def show_context_menu(self, position):
        menu = QMenu()

        kill_action = QAction("Kill Process", self)
        kill_action.triggered.connect(self.kill_selected_process)

        inject_action = QAction("Open in Injector", self)
        inject_action.triggered.connect(self.open_in_injector_clicked)

        dump_action = QAction("Dump APK", self)
        dump_action.triggered.connect(self.dump_apk)

        details_action = QAction("Process Details", self)
        details_action.triggered.connect(self.show_process_details)

        menu.addAction(kill_action)
        menu.addAction(inject_action)
        menu.addAction(dump_action)
        menu.addSeparator()
        menu.addAction(details_action)
        menu.exec_(self.process_table.mapToGlobal(position))

    def open_in_injector_clicked(self):
        """Handle click on 'Open in Injector' button"""
        if not self.main_window:
            return

        selected = self.process_table.selectedItems()
        if selected:
            row = selected[0].row()
            try:
                pid = int(self.process_table.item(row, 0).text())
                if self.current_device:
                    self.main_window.open_in_injector(self.current_device, pid)
                else:
                    QMessageBox.warning(self, "Error", "No device selected!")
            except ValueError:
                QMessageBox.critical(self, "Error", "Invalid PID format.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Error: {e}")

    def refresh_processes(self):
        """Refresh process list using ps command"""
        selected_pid = None
        if self.process_table.selectedItems():
            row = self.process_table.currentRow()
            if row != -1:
                selected_pid = self.process_table.item(row, 0).text()

        self.process_table.setSortingEnabled(False)
        self.process_table.setRowCount(0)
        self.processes.clear()

        if not self.current_device:
            return

        try:
            self.status_label.setText("Refreshing processes...")
            
            # Get process list using ps -A
            adb_output = subprocess.check_output(
                ['adb', '-s', self.current_device, 'shell', 'ps', '-A'],
                text=True,
                stderr=subprocess.DEVNULL
            ).strip().split('\n')

            # Get debuggable packages
            debuggable_pkgs = self.get_debuggable_packages()

            # Parse process list
            for line in adb_output[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 9:
                    try:
                        user = parts[0]
                        pid = parts[1]
                        # Remove leading 'S', 'R', 'D', etc. status indicators
                        name = parts[8] if len(parts) > 8 else parts[-1]
                        
                        # Clean up process name (remove status prefix if present)
                        if name and len(name) > 1 and name[0] in 'SDTRZX':
                            name = name[1:]
                        
                        status = parts[7] if len(parts) > 7 else 'Unknown'
                        
                        # Determine package name (for apps)
                        package = name if '.' in name else 'N/A'
                        
                        # Check if debuggable
                        is_debuggable = package in debuggable_pkgs
                        
                        process_info = {
                            'pid': pid,
                            'name': name,
                            'package': package,
                            'user': user,
                            'status': status,
                            'debuggable': is_debuggable
                        }
                        
                        self.processes.append(process_info)
                        
                    except (IndexError, ValueError) as e:
                        continue

            self.update_table()
            self.status_label.setText(f"Loaded {len(self.processes)} processes")

        except subprocess.CalledProcessError as e:
            print(f"ADB error: {e}")
            self.status_label.setText("Error: ADB command failed")
        except Exception as e:
            print(f"Error refreshing processes: {e}")
            self.status_label.setText(f"Error: {str(e)}")

        # Restore selection
        if selected_pid:
            for row in range(self.process_table.rowCount()):
                if self.process_table.item(row, 0).text() == selected_pid:
                    self.process_table.selectRow(row)
                    break

        self.process_table.setSortingEnabled(True)

    def get_debuggable_packages(self):
        """Get list of debuggable packages"""
        try:
            output = subprocess.check_output(
                ['adb', '-s', self.current_device, 'shell', 'pm', 'list', 'packages', '-d'],
                text=True,
                stderr=subprocess.DEVNULL
            )
            packages = set()
            for line in output.strip().split('\n'):
                if line.startswith('package:'):
                    packages.add(line.replace('package:', ''))
            return packages
        except:
            return set()

    def update_table(self):
        """Populate table with process data"""
        for process in self.processes:
            row = self.process_table.rowCount()
            self.process_table.insertRow(row)

            items = [
                QTableWidgetItem(process['pid']),
                QTableWidgetItem(process['name']),
                QTableWidgetItem(process['package']),
                QTableWidgetItem(process['user']),
                QTableWidgetItem(process['status']),
                QTableWidgetItem('✓ Yes' if process['debuggable'] else '✗ No')
            ]

            # Center align PID, User, Status, Debuggable
            items[0].setTextAlignment(Qt.AlignCenter)
            items[3].setTextAlignment(Qt.AlignCenter)
            items[4].setTextAlignment(Qt.AlignCenter)
            items[5].setTextAlignment(Qt.AlignCenter)

            # Color code debuggable apps
            if process['debuggable']:
                items[5].setForeground(QColor('#43b581'))

            # Add items to row
            for col, item in enumerate(items):
                self.process_table.setItem(row, col, item)

        self.apply_filters()
        self.process_count.setText(f"{self.process_table.rowCount()} processes")

    def apply_filters(self):
        """Apply search and filter criteria"""
        search_text = self.search_input.text().lower()
        filter_type = self.filter_combo.currentText()
        use_regex = self.regex_check.isChecked()

        visible_count = 0
        for row in range(self.process_table.rowCount()):
            show_row = True
            name_item = self.process_table.item(row, 1)
            package_item = self.process_table.item(row, 2)
            debuggable_item = self.process_table.item(row, 5)

            if not name_item:
                continue

            name = name_item.text().lower()
            package = package_item.text().lower() if package_item else ''

            # Apply text filter
            if search_text:
                if use_regex:
                    try:
                        if not (re.search(search_text, name) or re.search(search_text, package)):
                            show_row = False
                    except re.error:
                        show_row = False
                elif search_text not in name and search_text not in package:
                    show_row = False

            # Apply type filter
            if filter_type == 'User Apps' and '.' not in package:
                show_row = False
            elif filter_type == 'System' and '.' in package:
                show_row = False
            elif filter_type == 'Debuggable' and not debuggable_item.text().startswith('✓'):
                show_row = False

            self.process_table.setRowHidden(row, not show_row)
            if show_row:
                visible_count += 1

        self.process_count.setText(f"{visible_count} processes (of {self.process_table.rowCount()})")

    def kill_selected_process(self):
        """Kill the selected process (using a non-blocking thread)"""
        selected = self.process_table.selectedItems()
        if not selected:
            return

        row = selected[0].row()
        pid = self.process_table.item(row, 0).text()
        name = self.process_table.item(row, 1).text()
        
        reply = QMessageBox.question(
            self, 
            "Kill Process",
            f"Are you sure you want to kill process:\n{name} (PID: {pid})?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # 1. Create QThread instance
            self.thread = QThread()
            # 2. Create Worker instance
            self.worker = KillProcessWorker(self.current_device, pid, name)
            
            # 3. Move worker to the thread
            self.worker.moveToThread(self.thread)
            
            # 4. Connect signals to slots
            self.thread.started.connect(self.worker.run)
            self.worker.finished.connect(self._handle_kill_success)
            self.worker.error.connect(self._handle_kill_error)
            
            # 5. Clean up when finished/error (crucial!)
            self.worker.finished.connect(self.thread.quit)
            self.worker.error.connect(self.thread.quit)
            self.worker.finished.connect(self.worker.deleteLater)
            self.worker.error.connect(self.worker.deleteLater)
            self.thread.finished.connect(self.thread.deleteLater)
            
            # 6. Start the thread
            self.thread.start()

    def _handle_kill_success(self, pid, name):
        """Executed on the main thread after successful kill."""
        self.status_label.setText(f"Killed process {pid}: {name}")
        self.refresh_processes()

    def _handle_kill_error(self, error_msg):
        """Executed on the main thread after kill failure."""
        QMessageBox.critical(self, "Error", f"Failed to kill process:\n{error_msg}")

    def dump_apk(self):
        """Dump APK of selected app"""
        selected = self.process_table.selectedItems()
        if selected:
            row = selected[0].row()
            package = self.process_table.item(row, 2).text()
            
            if package == 'N/A' or '.' not in package:
                QMessageBox.warning(self, "Error", "Not an app package")
                return
            
            try:
                # Get APK path
                path_output = subprocess.check_output(
                    ['adb', '-s', self.current_device, 'shell', 'pm', 'path', package],
                    text=True
                ).strip()
                
                if not path_output.startswith('package:'):
                    raise Exception("Could not find APK path")
                
                apk_path = path_output.replace('package:', '')
                
                # Pull APK
                output_path = f"{package}.apk"
                subprocess.run(
                    ['adb', '-s', self.current_device, 'pull', apk_path, output_path],
                    check=True
                )
                
                QMessageBox.information(self, "Success", f"APK dumped to: {output_path}")
                
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to dump APK: {e}")

    def show_process_details(self):
        """Show detailed info about selected process"""
        selected = self.process_table.selectedItems()
        if selected:
            row = selected[0].row()
            details = "\n".join([
                f"{self.process_table.horizontalHeaderItem(col).text()}: "
                f"{self.process_table.item(row, col).text()}"
                for col in range(self.process_table.columnCount())
            ])
            QMessageBox.information(self, "Process Details", details)