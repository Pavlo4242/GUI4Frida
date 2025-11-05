from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
                           QFrame, QLabel, QPushButton, QComboBox, QLineEdit,
                           QTextEdit, QListWidget, QListWidgetItem, QGroupBox,
                           QApplication, QFileDialog, QMessageBox)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QTextCursor
import qtawesome as qta
from datetime import datetime


class CompactDeviceSelector(QWidget):
    """Compact device and process selector"""
    
    device_changed = pyqtSignal(str)  # device_id
    process_changed = pyqtSignal(int, str)  # pid, name
    refresh_requested = pyqtSignal()
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
        
    def setup_ui(self):
        """Setup compact selector UI"""
        # Main container with border
        container = QFrame()
        container.setObjectName("deviceSelector")
        container.setStyleSheet("""
            QFrame#deviceSelector {
                background-color: #2f3136;
                border-radius: 8px;
                padding: 12px;
            }
        """)
        
        layout = QVBoxLayout(container)
        layout.setSpacing(8)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Row 1: Device
        device_row = QHBoxLayout()
        device_label = QLabel("Device:")
        device_label.setStyleSheet("color: #96989d; font-weight: bold; min-width: 70px;")
        
        self.device_combo = QComboBox()
        self.device_combo.setMinimumWidth(200)
        self.device_combo.currentIndexChanged.connect(self._on_device_changed)
        
        self.refresh_device_btn = QPushButton(qta.icon('fa5s.sync', color='white'), "")
        self.refresh_device_btn.setFixedSize(32, 32)
        self.refresh_device_btn.setToolTip("Refresh devices")
        self.refresh_device_btn.clicked.connect(self.refresh_requested.emit)
        
        device_row.addWidget(device_label)
        device_row.addWidget(self.device_combo, 1)
        device_row.addWidget(self.refresh_device_btn)
        
        # Row 2: Process Filter
        filter_row = QHBoxLayout()
        filter_label = QLabel("Filter:")
        filter_label.setStyleSheet("color: #96989d; font-weight: bold; min-width: 70px;")
        
        self.process_filter = QLineEdit()
        self.process_filter.setPlaceholderText("Filter processes...")
        self.process_filter.textChanged.connect(self._apply_filter)
        
        filter_row.addWidget(filter_label)
        filter_row.addWidget(self.process_filter, 1)
        
        # Row 3: Process Selection
        process_row = QHBoxLayout()
        process_label = QLabel("Process:")
        process_label.setStyleSheet("color: #96989d; font-weight: bold; min-width: 70px;")
        
        self.process_combo = QComboBox()
        self.process_combo.setMinimumWidth(200)
        self.process_combo.currentIndexChanged.connect(self._on_process_changed)
        
        self.refresh_process_btn = QPushButton(qta.icon('fa5s.sync', color='white'), "")
        self.refresh_process_btn.setFixedSize(32, 32)
        self.refresh_process_btn.setToolTip("Refresh processes")
        
        self.spawn_btn = QPushButton(qta.icon('fa5s.rocket', color='white'), "Spawn")
        self.spawn_btn.setToolTip("Spawn new app")
        self.spawn_btn.setEnabled(False)
        
        process_row.addWidget(process_label)
        process_row.addWidget(self.process_combo, 1)
        process_row.addWidget(self.refresh_process_btn)
        process_row.addWidget(self.spawn_btn)
        
        layout.addLayout(device_row)
        layout.addLayout(filter_row)
        layout.addLayout(process_row)
        
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(container)
        
        self._all_processes = []
        
    def set_devices(self, devices):
        """Update device list"""
        current = self.device_combo.currentData()
        self.device_combo.clear()
        
        for device in devices:
            self.device_combo.addItem(
                f"📱 {device['name']} (USB)",
                device['id']
            )
            
        # Restore selection if possible
        if current:
            idx = self.device_combo.findData(current)
            if idx >= 0:
                self.device_combo.setCurrentIndex(idx)
                
    def set_processes(self, processes):
        """Update process list"""
        self._all_processes = processes
        self._apply_filter(self.process_filter.text())
        
    def _apply_filter(self, text):
        """Filter processes by text"""
        search = text.lower()
        self.process_combo.clear()
        
        for proc in self._all_processes:
            if search in proc['name'].lower():
                self.process_combo.addItem(
                    f"{proc['name']} (PID: {proc['pid']})",
                    (proc['pid'], proc['name'])
                )
                
    def _on_device_changed(self, index):
        """Handle device selection"""
        if index >= 0:
            device_id = self.device_combo.currentData()
            if device_id:
                self.device_changed.emit(device_id)
                self.spawn_btn.setEnabled(True)
                
    def _on_process_changed(self, index):
        """Handle process selection"""
        if index >= 0:
            data = self.process_combo.currentData()
            if data:
                pid, name = data
                self.process_changed.emit(pid, name)
                
    def select_process_by_pid(self, pid):
        """Select process by PID"""
        for i in range(self.process_combo.count()):
            data = self.process_combo.itemData(i)
            if data and data[0] == pid:
                self.process_combo.setCurrentIndex(i)
                return True
        return False


class RecentTargetsPanel(QWidget):
    """Recent injection targets panel"""
    
    target_selected = pyqtSignal(str, int, str)  # device_id, pid, name
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
        
    def setup_ui(self):
        """Setup recent targets UI"""
        # Container with styling matching injection history
        container = QGroupBox("Recent Targets")
        container.setObjectName("recentTargets")
        container.setStyleSheet("""
            QGroupBox#recentTargets {
                border: 1px solid #4f545c;
                border-radius: 4px;
                margin-top: 10px;
                padding-top: 15px;
                font-size: 11px;
                color: #b9bbbe;
                background-color: #2f3136;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 3px 0 3px;
            }
        """)
        
        layout = QVBoxLayout(container)
        layout.setContentsMargins(5, 10, 5, 5)
        layout.setSpacing(2)
        
        self.target_list = QListWidget()
        self.target_list.setStyleSheet("""
            QListWidget {
                background-color: #36393f;
                border: none;
                border-radius: 4px;
            }
            QListWidget::item {
                padding: 5px;
                color: #dcddde;
                border-radius: 3px;
            }
            QListWidget::item:hover {
                background-color: #40444b;
            }
            QListWidget::item:selected {
                background-color: #5865f2;
            }
        """)
        self.target_list.setMaximumHeight(150)
        self.target_list.itemClicked.connect(self._on_item_clicked)
        
        layout.addWidget(self.target_list)
        
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(container)
        
    def set_targets(self, targets):
        """Update recent targets list"""
        self.target_list.clear()
        
        for target in targets:
            pid_str = f"PID: {target['pid']}" if target['pid'] > 0 else "SPAWN"
            item = QListWidgetItem(f"{target['name']} ({pid_str})")
            item.setData(Qt.UserRole, target)
            item.setToolTip(f"Device: {target['device_id']}")
            self.target_list.addItem(item)
            
    def _on_item_clicked(self, item):
        """Handle target selection"""
        target = item.data(Qt.UserRole)
        if target:
            self.target_selected.emit(
                target['device_id'],
                target['pid'],
                target['name']
            )


class TimestampedOutputPanel(QWidget):
    """Output panel with timestamps and session management"""
    
    def __init__(self, title="Output"):
        super().__init__()
        self._title = title
        self._current_session_id = None
        self.setup_ui()
        
    def setup_ui(self):
        """Setup output panel UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Header
        header = QFrame()
        header.setStyleSheet("QFrame { background-color: #2f3136; padding: 4px 8px; }")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(0, 0, 0, 0)
        
        self.title_label = QLabel(self._title)
        self.title_label.setStyleSheet("font-weight: bold; color: #dcddde; font-size: 12px;")
        
        self.clear_btn = QPushButton(qta.icon('fa5s.trash-alt', color='#f04747'), "")
        self.clear_btn.setFlat(True)
        self.clear_btn.setFixedSize(24, 24)
        self.clear_btn.setToolTip("Clear output")
        self.clear_btn.clicked.connect(self.clear)
        
        header_layout.addWidget(self.title_label)
        header_layout.addStretch()
        header_layout.addWidget(self.clear_btn)
        
        # Output area
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(QFont("Consolas", 10))
        self.output.setStyleSheet("""
            QTextEdit {
                background-color: #202225;
                color: #dcddde;
                border: none;
                padding: 8px;
            }
        """)
        
        layout.addWidget(header)
        layout.addWidget(self.output)
        
    def append(self, timestamp, message):
        """Append message with timestamp"""
        formatted = f"<span style='color: #96989d;'>[{timestamp}]</span> {self._format_message(message)}"
        self.output.append(formatted)
        
        # Auto-scroll to bottom
        cursor = self.output.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.output.setTextCursor(cursor)
        
    def _format_message(self, message):
        """Format message with color coding"""
        msg_lower = message.lower()
        
        if '[error]' in msg_lower or 'failed' in msg_lower:
            return f"<span style='color: #f04747;'>{message}</span>"
        elif '[+]' in message or 'success' in msg_lower:
            return f"<span style='color: #43b581;'>{message}</span>"
        elif '[*]' in message:
            return f"<span style='color: #faa61a;'>{message}</span>"
        else:
            return message
            
    def insert_session_separator(self):
        """Insert visual separator for new session"""
        separator = "<hr style='border: 1px solid #40444b; margin: 10px 0;' />"
        self.output.append(separator)
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.output.append(f"<span style='color: #7289da; font-weight: bold;'>[{timestamp}] === NEW SESSION ===</span>")
        
    def clear(self):
        """Clear output"""
        self.output.clear()
        
    def start_new_session(self, session_id):
        """Start new output session"""
        if self._current_session_id != session_id:
            if self._current_session_id is not None:
                self.insert_session_separator()
            self._current_session_id = session_id


class InjectionControlPanel(QWidget):
    """Injection control buttons and REPL"""
    
    inject_clicked = pyqtSignal()
    stop_clicked = pyqtSignal()
    load_clicked = pyqtSignal()
    save_clicked = pyqtSignal(str)  # name
    clear_clicked = pyqtSignal()
    message_sent = pyqtSignal(str)  # message
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
        
    def setup_ui(self):
        """Setup control panel UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        
        # Status display
        status_frame = QFrame()
        status_frame.setStyleSheet("""
            QFrame {
                background-color: #2f3136;
                border-radius: 6px;
                padding: 8px;
            }
        """)
        status_layout = QHBoxLayout(status_frame)
        status_layout.setContentsMargins(0, 0, 0, 0)
        
        self.status_icon = QLabel()
        self.status_icon.setPixmap(qta.icon('fa5s.circle', color='#99aab5').pixmap(12, 12))
        
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #dcddde; font-size: 12px;")
        
        status_layout.addWidget(self.status_icon)
        status_layout.addWidget(self.status_label)
        status_layout.addStretch()
        
        # Save script row
        save_layout = QHBoxLayout()
        save_layout.setSpacing(6)
        
        self.save_name = QLineEdit()
        self.save_name.setPlaceholderText("Script name (e.g., 'my_hook')")
        self.save_name.setStyleSheet("padding: 6px;")
        
        js_label = QLabel(".js")
        js_label.setStyleSheet("color: #96989d; font-weight: bold;")
        
        self.save_btn = QPushButton(qta.icon('fa5s.save', color='white'), " Save")
        self.save_btn.clicked.connect(self._on_save)
        self.save_btn.setStyleSheet("""
            QPushButton {
                background-color: #7289da;
                padding: 6px 12px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #677bc4;
            }
        """)
        
        save_layout.addWidget(self.save_name, 1)
        save_layout.addWidget(js_label)
        save_layout.addWidget(self.save_btn)
        
        # Control buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(6)
        
        self.load_btn = QPushButton(qta.icon('fa5s.folder-open', color='white'), " Load")
        self.load_btn.clicked.connect(self.load_clicked.emit)
        
        self.clear_btn = QPushButton(qta.icon('fa5s.trash-alt', color='white'), " Clear")
        self.clear_btn.clicked.connect(self.clear_clicked.emit)
        
        btn_layout.addWidget(self.load_btn)
        btn_layout.addWidget(self.clear_btn)
        btn_layout.addStretch()
        
        self.inject_btn = QPushButton(qta.icon('fa5s.syringe', color='white'), " Inject")
        self.inject_btn.clicked.connect(self.inject_clicked.emit)
        self.inject_btn.setEnabled(False)
        self.inject_btn.setStyleSheet("""
            QPushButton {
                background-color: #43b581;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #3ca374;
            }
            QPushButton:disabled {
                background-color: #2f3136;
                color: #72767d;
            }
        """)
        
        self.stop_btn = QPushButton(qta.icon('fa5s.stop', color='white'), " Stop")
        self.stop_btn.clicked.connect(self.stop_clicked.emit)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background-color: #f04747;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #d84040;
            }
            QPushButton:disabled {
                background-color: #2f3136;
                color: #72767d;
            }
        """)
        
        btn_layout.addWidget(self.inject_btn)
        btn_layout.addWidget(self.stop_btn)
        
        # REPL (taller input)
        repl_layout = QHBoxLayout()
        repl_layout.setSpacing(6)
        
        self.message_input = QTextEdit()
        self.message_input.setPlaceholderText("Send message to script (Ctrl+Enter to send)...")
        self.message_input.setMaximumHeight(60)
        self.message_input.setStyleSheet("padding: 6px;")
        self.message_input.setEnabled(False)
        
        # Install event filter for Ctrl+Enter
        self.message_input.installEventFilter(self)
        
        self.send_btn = QPushButton(qta.icon('fa5s.paper-plane', color='white'), "")
        self.send_btn.setFixedSize(40, 60)
        self.send_btn.clicked.connect(self._send_message)
        self.send_btn.setEnabled(False)
        self.send_btn.setStyleSheet("""
            QPushButton {
                background-color: #5865f2;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #4752c4;
            }
            QPushButton:disabled {
                background-color: #2f3136;
            }
        """)
        
        repl_layout.addWidget(self.message_input)
        repl_layout.addWidget(self.send_btn)
        
        # Add all to main layout
        layout.addWidget(status_frame)
        layout.addLayout(save_layout)
        layout.addLayout(btn_layout)
        layout.addLayout(repl_layout)
        
    def eventFilter(self, obj, event):
        """Handle Ctrl+Enter in message input"""
        if obj == self.message_input:
            from PyQt5.QtCore import QEvent
            from PyQt5.QtGui import QKeyEvent
            if event.type() == QEvent.KeyPress:
                if event.key() == Qt.Key_Return and event.modifiers() == Qt.ControlModifier:
                    self._send_message()
                    return True
        return super().eventFilter(obj, event)
        
    def _send_message(self):
        """Send message to script"""
        text = self.message_input.toPlainText().strip()
        if text:
            self.message_sent.emit(text)
            self.message_input.clear()
            
    def _on_save(self):
        """Handle save button"""
        name = self.save_name.text().strip()
        if name:
            self.save_clicked.emit(name)
            self.save_name.clear()
            
    def set_status(self, text, color='#99aab5'):
        """Update status display"""
        self.status_label.setText(text)
        self.status_icon.setPixmap(qta.icon('fa5s.circle', color=color).pixmap(12, 12))
        
    def set_state(self, state):
        """Update button states based on injection state"""
        # state: idle, injecting, running, stopping
        self.inject_btn.setEnabled(state == 'idle')
        self.stop_btn.setEnabled(state == 'running')
        self.message_input.setEnabled(state == 'running')
        self.send_btn.setEnabled(state == 'running')
        
        can_edit = state in ['idle', 'stopped']
        self.load_btn.setEnabled(can_edit)
        self.clear_btn.setEnabled(can_edit)
        self.save_btn.setEnabled(can_edit)
        self.save_name.setEnabled(can_edit)


class InjectionView(QWidget):
    """Main injection view with improved layout"""
    
    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self.setup_ui()
        self.connect_signals()
        
    def setup_ui(self):
        """Setup main injection view"""
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Top section: Device selector + Recent targets side by side
        top_splitter = QSplitter(Qt.Horizontal)
        
        self.device_selector = CompactDeviceSelector()
        self.recent_targets = RecentTargetsPanel()
        
        top_splitter.addWidget(self.device_selector)
        top_splitter.addWidget(self.recent_targets)
        top_splitter.setSizes([600, 250])
        
        # Middle: Script editor
        self.script_editor = QTextEdit()
        self.script_editor.setPlaceholderText("Enter your Frida script here...")
        self.script_editor.setFont(QFont("Consolas", 12))
        self.script_editor.setStyleSheet("""
            QTextEdit {
                background-color: #202225;
                color: #dcddde;
                border: 1px solid #40444b;
                border-radius: 4px;
                padding: 10px;
            }
        """)
        
        # Bottom: Outputs (script + logs side by side)
        output_splitter = QSplitter(Qt.Horizontal)
        
        self.script_output = TimestampedOutputPanel("Script Output (console.log / send)")
        self.app_log = TimestampedOutputPanel("Application Logs")
        
        output_splitter.addWidget(self.script_output)
        output_splitter.addWidget(self.app_log)
        output_splitter.setSizes([400, 300])
        
        # Controls
        self.control_panel = InjectionControlPanel()
        
        # Main vertical splitter
        main_splitter = QSplitter(Qt.Vertical)
        main_splitter.addWidget(top_splitter)
        main_splitter.addWidget(self.script_editor)
        main_splitter.addWidget(output_splitter)
        main_splitter.addWidget(self.control_panel)
        main_splitter.setSizes([120, 350, 250, 120])
        
        layout.addWidget(main_splitter)
        
    def connect_signals(self):
        """Connect view signals to controller"""
        # Device selection
        self.device_selector.device_changed.connect(
            self.controller.device_model.select_device
        )
        self.device_selector.refresh_requested.connect(
            self.controller.device_model.refresh_devices
        )
        
        # Process selection
        self.device_selector.process_changed.connect(
            lambda pid, name: self.controller.process_model.select_process(
                self.controller.device_model.current_device_id,
                pid,
                name
            )
        )
        
        # Recent targets
        self.recent_targets.target_selected.connect(self._on_recent_target_selected)
        
        # Control panel
        self.control_panel.inject_clicked.connect(self._on_inject)
        self.control_panel.stop_clicked.connect(
            self.controller.injection_controller.stop_injection
        )
        self.control_panel.load_clicked.connect(self._load_script)
        self.control_panel.save_clicked.connect(self._save_script)
        self.control_panel.clear_clicked.connect(self.script_editor.clear)
        self.control_panel.message_sent.connect(
            self.controller.injection_controller.post_message
        )
        
        # Model updates
        self.controller.device_model.devices_changed.connect(
            self.device_selector.set_devices
        )
        self.controller.process_model.processes_changed.connect(
            self.device_selector.set_processes
        )
        self.controller.process_model.recent_targets_changed.connect(
            self.recent_targets.set_targets
        )
        
        # Script model updates
        self.controller.script_model.injection_state_changed.connect(
            self._on_injection_state_changed
        )
        self.controller.script_model.output_received.connect(
            self.script_output.append
        )
        
        # Injection controller
        self.controller.injection_controller.injection_succeeded.connect(
            self._on_injection_success
        )
        self.controller.injection_controller.injection_failed.connect(
            self._on_injection_failed
        )
        
    def _on_inject(self):
        """Handle inject button"""
        script = self.script_editor.toPlainText()
        self.controller.script_model.set_script_content(script)
        self.controller.injection_controller.inject_script()
        
    def _load_script(self):
        """Load script from file"""
        scripts_dir = os.path.join(os.getcwd(), 'frida_data', 'scripts')
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Load Script",
            scripts_dir,
            "JavaScript Files (*.js);;All Files (*)"
        )
        
        if file_path:
            self.controller.script_model.load_script(file_path)
            self.script_editor.setPlainText(self.controller.script_model.script_content)
            
    def _save_script(self, name):
        """Save script to file"""
        scripts_dir = os.path.join(os.getcwd(), 'frida_data', 'scripts')
        os.makedirs(scripts_dir, exist_ok=True)
        
        file_path = os.path.join(scripts_dir, f"{name}.js")
        script_content = self.script_editor.toPlainText()
        
        self.controller.script_model.save_script(file_path, script_content)
        QMessageBox.information(self, "Success", f"Script saved to:\n{file_path}")
        
    def _on_recent_target_selected(self, device_id, pid, name):
        """Handle recent target selection"""
        self.controller.device_model.select_device(device_id)
        
        # Wait a bit for processes to refresh, then select
        QTimer.singleShot(200, lambda: self.device_selector.select_process_by_pid(pid))
        
    def _on_injection_state_changed(self, state):
        """Handle injection state changes"""
        self.control_panel.set_state(state)
        
        status_map = {
            'idle': ('Ready', '#99aab5'),
            'injecting': ('Injecting...', '#faa61a'),
            'running': (f'Running in PID: {self.controller.process_model.current_pid}', '#43b581'),
            'stopping': ('Stopping...', '#faa61a'),
            'stopped': ('Stopped', '#99aab5')
        }
        
        if state in status_map:
            text, color = status_map[state]
            self.control_panel.set_status(text, color)
            
        # Start new output session when injecting
        if state == 'injecting':
            session_id = self.controller.script_model.get_session_id()
            self.script_output.start_new_session(session_id)
            
    def _on_injection_success(self):
        """Handle successful injection"""
        self.app_log.append(
            datetime.now().strftime("%H:%M:%S"),
            "[+] Script injected successfully"
        )
        
    def _on_injection_failed(self, error):
        """Handle injection failure"""
        self.app_log.append(
            datetime.now().strftime("%H:%M:%S"),
            f"[-] Injection failed: {error}"
        )