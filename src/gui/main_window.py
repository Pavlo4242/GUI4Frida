from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                           QPushButton, QStackedWidget, QLabel, QListWidget, QTableWidget,
                           QGroupBox, QCheckBox, QSpinBox, QMessageBox, QScrollArea,
                           QGridLayout, QLineEdit, QTextEdit, QFrame, QDialog, QFileDialog,
                           QSplitter, QApplication)
from PyQt5.QtCore import Qt, QSize, pyqtSlot, QTimer, QThread, QObject, pyqtSignal # MODIFICATION: Added threading imports
from PyQt5.QtGui import QFont
import qtawesome as qta
from .widgets.device_panel import DevicePanel
from .widgets.process_panel import ProcessPanel
from .widgets.script_editor import ScriptEditorPanel
# MODIFICATION: OutputPanel is still needed
from .widgets.output_panel import OutputPanel
from .widgets.codeshare_browser import CodeShareBrowser
from .widgets.app_launcher import AppLauncher
from .widgets.process_monitor import ProcessMonitor as ProcessMonitorWidget
from .widgets.injection_panel import InjectionPanel
from .widgets.device_selector import DeviceSelector
from .widgets.history_page import HistoryPage
from core.history_manager import HistoryManager
from core.android_helper import AndroidHelper
import frida
import subprocess
import os
import json
import requests
import sys

SETTINGS_DIR = os.path.join(os.path.expanduser('~'), '.frida_gui')
FAVORITES_FILE = os.path.join(SETTINGS_DIR, 'favorites.json')

class StopScriptWorker(QObject):
    finished = pyqtSignal(bool, str) # process_ended, pid_context

    def __init__(self, script, session, pid_context, process_ended=False, parent=None):
        super().__init__(parent)
        self.script = script
        self.session = session
        self.pid_context = pid_context
        self.process_ended = process_ended

    def run(self):
        # Perform the blocking calls safely in the thread
        if self.script:
            try:
                self.script.unload()
            except Exception as e:
                print(f"[StopScriptWorker] Error unloading: {e}")
        
        if self.session and not self.session.is_detached:
            try:
                self.session.detach()
            except Exception as e:
                print(f"[StopScriptWorker] Error detaching: {e}")
                
        self.finished.emit(self.process_ended, self.pid_context)


class FridaInjectorMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Oliver Stankiewicz's | Frida Script Manager")
        self.setMinimumSize(1400, 800)
        self.history_manager = HistoryManager()
        self.favorites = []
        self.load_favorites()
        self.current_device = None
        self.current_pid = None
        self.spawn_target = None
        self.current_session = None
        self.current_script = None
        self.pages = {}
        self.setup_ui()
        self.init_pages()
        
        if hasattr(self, 'codeshare_browser'):
            self.codeshare_browser.favorites_updated.connect(self.refresh_favorites)
            

    def load_favorites(self):
        """Loads favorites list from the JSON file."""
        try:
            if os.path.exists(FAVORITES_FILE):
                with open(FAVORITES_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    loaded_scripts = data.get('scripts', [])
                    self.favorites = loaded_scripts if isinstance(loaded_scripts, list) else []
                    print(f"[Favorites] Loaded {len(self.favorites)} favorites.")
            else:
                self.favorites = []
                print("[Favorites] No favorites file found, starting empty.")
        except Exception as e:
            print(f"[Favorites] Error loading favorites: {e}. Starting empty.")
            self.favorites = []

    def save_favorites(self):
        """Saves favorites list to the JSON file."""
        try:
            os.makedirs(SETTINGS_DIR, exist_ok=True)
            with open(FAVORITES_FILE, 'w', encoding='utf-8') as f:
                json.dump({'scripts': self.favorites}, f, indent=2)
            print(f"[Favorites] Saved {len(self.favorites)} favorites.")
        except Exception as e:
            print(f"[Favorites] Error saving favorites: {e}")

    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QHBoxLayout(central_widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        sidebar = self.create_sidebar()
        layout.addWidget(sidebar)
        self.stack = QStackedWidget()
        layout.addWidget(self.stack)
        layout.setStretch(0, 1)
        layout.setStretch(1, 4)
        
        return sidebar


    def create_sidebar(self):
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar.setStyleSheet("""
            QWidget#sidebar {
                background-color: #2f3136;
                border-right: 1px solid #202225;
                min-width: 180px;
                max-width: 180px;
            }
            QPushButton {
                text-align: left; padding: 6px 8px; border: none;
                border-radius: 4px; margin: 1px 4px;
                min-height: 32px; max-height: 32px; font-size: 13px;
                color: #b9bbbe; background-color: transparent;
            }
            QPushButton:hover { background-color: #36393f; color: #ffffff; }
            QPushButton:checked { background-color: #404249; color: #ffffff; }
        """)
        layout = QVBoxLayout(sidebar)
        layout.setSpacing(1); layout.setContentsMargins(0, 5, 0, 5)
        self.nav_buttons = {}
        nav_items = [
            ("home", "Home", "fa5s.home"),
            ("inject", "Script Injection", "fa5s.syringe"),
            ("codeshare", "CodeShare", "fa5s.cloud-download-alt"),
            ("favorites", "Favorites", "fa5s.star"),
            ("history", "History", "fa5s.history"),
            ("monitor", "Process Monitor", "fa5s.desktop"),
            ("settings", "Settings", "fa5s.cog")
        ]
        for id_, text, icon in nav_items:
            btn = QPushButton(qta.icon(icon, color='#b9bbbe'), f" {text}")
            btn.setCheckable(True)
            btn.clicked.connect(lambda checked, page_id=id_: self.switch_page(page_id))
            btn.setIconSize(QSize(14, 14))
            self.nav_buttons[id_] = btn
            layout.addWidget(btn)
        layout.addStretch()
        status_layout = QHBoxLayout(); status_layout.setContentsMargins(8, 4, 8, 4)
        self.status_icon = QLabel(); self.status_icon.setPixmap(qta.icon('fa5s.circle', color='#43b581').pixmap(8, 8))
        self.status_text = QLabel("Ready"); self.status_text.setStyleSheet("color: #b9bbbe; font-size: 12px;")
        status_layout.addWidget(self.status_icon); status_layout.addWidget(self.status_text)
        layout.addLayout(status_layout)
        return sidebar

    def init_pages(self):
        self.pages = {
            'home': None, 'inject': None, 'codeshare': None, 
            'favorites': None, 'history': None, 'monitor': None, 'settings': None
        }

        # Attempt to create each page and store it in the self.pages dictionary.
        try: self.pages['home'] = self.create_home_page()
        except Exception as e: print(f"Error creating home page: {e}")
        
        try: self.pages['inject'] = self.create_injection_page()
        except Exception as e: print(f"Error creating injection page: {e}")
        
        try: self.pages['codeshare'] = self.create_codeshare_page()
        except Exception as e: print(f"Error creating codeshare page: {e}")
        
        try: self.pages['favorites'] = self.create_favorites_page()
        except Exception as e: print(f"Error creating favorites page: {e}")
        
        try: self.pages['history'] = self.create_history_page()
        except Exception as e: print(f"Error creating history page: {e}")
        
        try: self.pages['monitor'] = self.create_monitor_page()
        except Exception as e: print(f"Error creating monitor page: {e}")
        
        try: self.pages['settings'] = self.create_settings_page()
        except Exception as e: print(f"Error creating settings page: {e}")

        for page_id, page_widget in self.pages.items():
            if page_widget:
                self.stack.addWidget(page_widget)
            else:
                if page_id in self.nav_buttons:
                    self.nav_buttons[page_id].setEnabled(False)
                    print(f"Disabled nav button for failed page: {page_id}")

        # Set the initial page to 'home'.
        initial_page = 'home'
        if initial_page in self.pages and self.pages[initial_page]:
            self.stack.setCurrentWidget(self.pages[initial_page])
            if initial_page in self.nav_buttons:
                self.nav_buttons[initial_page].setChecked(True)
        # Fallback to the first available page if 'home' failed to create.
        elif any(self.pages.values()):
            # Find the first valid page ID from the nav_buttons order
            valid_page_ids = [pid for pid in self.nav_buttons if pid in self.pages and self.pages[pid]]
            if valid_page_ids:
                first_page_id = valid_page_ids[0]
                self.stack.setCurrentWidget(self.pages[first_page_id])
                if first_page_id in self.nav_buttons:
                    self.nav_buttons[first_page_id].setChecked(True)


    def switch_page(self, page_id):
        if page_id not in self.pages or not self.pages[page_id]:
            print(f"Error: Cannot switch to non-existent page '{page_id}'.")
            return
        target_widget = self.pages[page_id]
        if self.stack.currentWidget() == target_widget: return
        for id_, btn in self.nav_buttons.items():
            if btn: btn.setChecked(id_ == page_id)
        self.stack.setCurrentWidget(target_widget)
        print(f"[MainWindow] Switched to page: {page_id}")

    def create_home_page(self):
        page = QWidget(); layout = QVBoxLayout(page); layout.setSpacing(20); layout.setContentsMargins(20, 20, 20, 20)
        header = QFrame(); header.setStyleSheet("QFrame { background-color: #2f3136; border-radius: 10px; padding: 20px; } QLabel { color: white; }")
        header_layout = QVBoxLayout(header)
        title = QLabel("Welcome to Frida Script Manager"); title.setStyleSheet("font-size: 24px; font-weight: bold;")
        subtitle = QLabel("A powerful GUI tool for Frida script management and injection"); subtitle.setStyleSheet("font-size: 16px; color: #b9bbbe;")
        author = QLabel("Created by Oliver Stankiewicz"); author.setStyleSheet("font-size: 14px; color: #7289da;")
        header_layout.addWidget(title); header_layout.addWidget(subtitle); header_layout.addWidget(author)
        actions = QFrame(); actions.setStyleSheet("QFrame { background-color: #2f3136; border-radius: 10px; padding: 20px; } QLabel { color: white; } QPushButton { background-color: #7289da; border-radius: 5px; padding: 10px; color: white; text-align: left; font-size: 14px; } QPushButton:hover { background-color: #677bc4; }")
        actions_layout = QVBoxLayout(actions); actions_title = QLabel("Quick Actions"); actions_title.setStyleSheet("font-size: 18px; font-weight: bold; margin-bottom: 10px;")
        inject_btn = QPushButton(qta.icon('fa5s.syringe'), " Script Injection"); inject_btn.clicked.connect(lambda: self.switch_page('inject'))
        browse_btn = QPushButton(qta.icon('fa5s.cloud-download-alt'), " Browse CodeShare"); browse_btn.clicked.connect(lambda: self.switch_page('codeshare'))
        favorites_btn = QPushButton(qta.icon('fa5s.star'), " View Favorites"); favorites_btn.clicked.connect(lambda: self.switch_page('favorites'))
        monitor_btn = QPushButton(qta.icon('fa5s.desktop'), " Process Monitor"); monitor_btn.clicked.connect(lambda: self.switch_page('monitor'))
        actions_layout.addWidget(actions_title); actions_layout.addWidget(inject_btn); actions_layout.addWidget(browse_btn); actions_layout.addWidget(favorites_btn); actions_layout.addWidget(monitor_btn)
        layout.addWidget(header); layout.addWidget(actions); layout.addStretch()
        return page

    # MODIFICATION: This function is heavily modified to create the new layout
    def create_injection_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        try:
            self.device_selector = DeviceSelector()
            self.script_editor = ScriptEditorPanel()
            self.injection_panel = InjectionPanel()
            
            # MODIFICATION: Setup output panels with titles (enabling clear buttons)
            self.script_output_panel = OutputPanel()
            self.script_output_panel.set_title("Script Output (console.log / send)") 
            self.script_output_panel.output_area.setPlaceholderText("Script output (from send() and console.log()) will appear here...")

            self.log_panel = OutputPanel()
            self.log_panel.set_title("Application Logs / Status") 
            self.log_panel.output_area.setPlaceholderText("Application logs (e.g., 'Attached', 'Script loaded', 'Error') will appear here...")
            
        except NameError as ne:
            print(f"Error instantiating injection widgets: {ne}. Check imports.")
            QMessageBox.critical(self, "Init Error", f"Failed to create injection UI component: {ne}")
            return None
            
        # Connect signals for injection start/stop and the new REPL message
        self.injection_panel.injection_started.connect(self.handle_injection_request)
        self.injection_panel.injection_stopped.connect(self.stop_injection)
        self.injection_panel.message_posted.connect(self.post_message_to_script)

        # Link script editor to injection panel
        editor_widget = self.script_editor.get_editor_widget()
        if editor_widget:
            if hasattr(self.injection_panel, 'set_script_editor_widget'):
                self.injection_panel.set_script_editor_widget(editor_widget)
                print("[MainWindow] Linked InjectionPanel to ScriptEditorPanel's editor.")
            else:
                print("CRITICAL ERROR: InjectionPanel has no 'set_script_editor_widget' method!")
                QMessageBox.critical(self, "Code Error", "InjectionPanel is missing 'set_script_editor_widget'. Cannot link editor.")
                return None
        else:
            print("CRITICAL ERROR: Could not get editor widget from ScriptEditorPanel!")
            QMessageBox.critical(self, "Init Error", "Failed to get script editor widget.")
            return None

        # MODIFICATION: Setup splitters (Vertical splits main area, horizontal splits logs)
        editor_vs_outputs_splitter = QSplitter(Qt.Vertical)
        editor_vs_outputs_splitter.addWidget(self.script_editor)

        outputs_splitter = QSplitter(Qt.Vertical)
        outputs_splitter.addWidget(self.script_output_panel)
        outputs_splitter.addWidget(self.log_panel)
        outputs_splitter.setSizes([250, 100])

        editor_vs_outputs_splitter.addWidget(outputs_splitter)
        editor_vs_outputs_splitter.setSizes([400, 350])

        layout.addWidget(self.device_selector)
        layout.addWidget(editor_vs_outputs_splitter)
        layout.addWidget(self.injection_panel)
        
        try:
            self.device_selector.process_selected.connect(self._update_current_selection)
            self.device_selector.application_selected_for_spawn.connect(self._update_spawn_target)
            self.device_selector.process_selected.connect(self.injection_panel.set_process)

        except TypeError as te:
            print(f"SIGNAL/SLOT TYPE ERROR during connection: {te}")
            QMessageBox.critical(self, "Signal/Slot Error", f"Connection failed due to type mismatch: {te}\nCheck @pyqtSlot decorators and signal definitions.")
            return None
        return page

    @pyqtSlot(str, int, int)
    def _update_current_selection(self, device_id, pid):
        # This slot handles the selection of a currently running process.
        pid_int = None
        if pid is not None:
            try:
                pid_int = int(pid)
                if pid_int <= 0: pid_int = None
            except (ValueError, TypeError):
                pid_int = None
        else: pid_int = None
        
        self.current_device = device_id
        self.current_pid = pid_int
        # Clear the spawn target, as we are now in "attach" mode.
        self.spawn_target = None
        
        status_text = "Ready"; icon_color = '#99aab5'
        if self.current_device and self.current_pid:
            status_text = f"PID: {self.current_pid} @ {self.current_device}"; icon_color = '#43b581'
        elif self.current_device:
            status_text = f"Device: {self.current_device} | No process"; icon_color = '#faa61a'
        else:
            status_text = "No device selected"
        self.status_text.setText(status_text)
        self.status_icon.setPixmap(qta.icon('fa5s.circle', color=icon_color).pixmap(10, 10))
        print(f"[MainWindow] Selection Updated: Device={self.current_device}, PID={self.current_pid}")

    @pyqtSlot(str, str, list, str)
    def _update_spawn_target(self, device_id, app_identifier, script_paths, frida_options):
        """
        Handles spawn request with multiple scripts in sequence.
        Called when user selects app + multiple scripts + Frida options.
        """
        self.current_device = device_id
        self.spawn_target = app_identifier
        self.current_pid = None  # Clear PID until spawn completes

        # Update status bar
        status_text = f"Spawn: {self.spawn_target} @ {self.current_device}"
        self.status_text.setText(status_text)
        self.status_icon.setPixmap(qta.icon('fa5s.circle', color='#7289da').pixmap(10, 10))

        print(f"[MainWindow] Spawn Target Set: {app_identifier} on {device_id}")
        print(f"    Scripts: {len(script_paths)}")
        print(f"    Options: {frida_options}")

        # Switch to inject page
        self.switch_page('inject')

        # Start the multi-script spawn sequence
        self._start_multi_script_spawn(device_id, app_identifier, script_paths, frida_options)

        
    def _start_multi_script_spawn(self, device_id, app_identifier, script_paths, frida_options):
        """Launches app and injects scripts one by one."""
        try:
            device = frida.get_device(device_id)
            if device.type == 'usb' and not AndroidHelper.is_frida_running(device_id):
                raise Exception("Frida server not running on device.")

            # MODIFICATION: Log to the new log_panel
            self.log_panel.append_output(f"[*] Spawning '{app_identifier}'...")
            print(f"[Spawn] Spawning {app_identifier}...")
            pid = device.spawn([app_identifier])

            # Update state with new PID
            self._update_current_selection(device_id, pid)
            # MODIFICATION: Log to the new log_panel
            self.log_panel.append_output(f"[+] Spawned PID: {pid}")

            # Resume only after ALL scripts are loaded
            base_cmd = ["frida", "-D", device_id, "-n", str(pid)]
            if frida_options:
                base_cmd.extend(frida_options.split())

            # Inject each script in order
            for i, script_path in enumerate(script_paths):
                # MODIFICATION: Log to the new log_panel
                self.log_panel.append_output(f"[*] Loading script {i+1}/{len(script_paths)}: {os.path.basename(script_path)}")
                print(f"  → Running script {i+1}: {script_path}")

                cmd = base_cmd.copy()
                # MODIFICATION: Pass the script path directly to Frida instead of using stdin.
                # This is more robust and avoids issues with stdin piping.
                cmd.extend(["-l", script_path])

                try:
                    # MODIFICATION: We no longer need to read the script or pipe it.
                    # Frida will read the file from the path we provided.
                    proc = subprocess.Popen(
                        cmd,
                        # stdin is no longer needed
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    # MODIFICATION: No input is passed to communicate()
                    stdout, stderr = proc.communicate()

                    if proc.returncode == 0:
                        # MODIFICATION: Log to the new log_panel
                        self.log_panel.append_output(f"[+] Script {i+1} injected.")
                        print(f"  Success: Script {i+1} completed.")
                    else:
                        err = stderr.strip() or "Unknown error"
                        # MODIFICATION: Log to the new log_panel
                        self.log_panel.append_output(f"[-] Script {i+1} failed: {err}")
                        print(f"  Failed: {err}")
                        # Continue to next script or break?
                        # break  # Uncomment to stop on first error

                except Exception as e:
                    # MODIFICATION: Log to the new log_panel
                    self.log_panel.append_output(f"[-] Error running script {i+1}: {e}")
                    print(f"  Error: {e}")

            # Final resume
            print(f"[Spawn] Resuming PID {pid}...")
            device.resume(pid)
            # MODIFICATION: Log to the new log_panel
            self.log_panel.append_output(f"[*] Resumed PID: {pid}")
            self.log_panel.append_output("[+] All scripts injected and app resumed.")

            # Trigger injection panel success
            if hasattr(self, 'injection_panel'):
                self.injection_panel.injection_succeeded()

        except Exception as e:
            error_msg = str(e)
            # MODIFICATION: Log to the new log_panel
            self.log_panel.append_output(f"[-] Spawn failed: {error_msg}")
            print(f"[Spawn] Failed: {error_msg}")
            if hasattr(self, 'injection_panel'):
                self.injection_panel.injection_failed(error_msg)

    def create_codeshare_page(self):
        page = QWidget(); layout = QVBoxLayout(page); layout.setContentsMargins(0,0,0,0)
        self.codeshare_browser = CodeShareBrowser()
        self.codeshare_browser.open_in_injector.connect(self.open_script_in_injector)
        layout.addWidget(self.codeshare_browser)
        return page

    def create_favorites_page(self):
        page = QWidget(); layout = QVBoxLayout(page); layout.setContentsMargins(10, 10, 10, 10); layout.setSpacing(10)
        toolbar = QHBoxLayout(); search_input = QLineEdit(); search_input.setPlaceholderText("Search favorites..."); search_input.textChanged.connect(self.filter_favorites)
        upload_btn = QPushButton(qta.icon('fa5s.file-upload'), "Upload Script"); upload_btn.clicked.connect(self.upload_script)
        toolbar.addWidget(search_input); toolbar.addWidget(upload_btn)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); scroll.setStyleSheet("QScrollArea { border: none; background-color: #36393f; }")
        self.favorites_grid = QWidget(); self.favorites_grid.setStyleSheet("QWidget { background-color: #36393f; }")
        self.favorites_grid_layout = QGridLayout(self.favorites_grid); self.favorites_grid_layout.setSpacing(10); self.favorites_grid_layout.setContentsMargins(15, 15, 15, 15)
        scroll.setWidget(self.favorites_grid); layout.addLayout(toolbar); layout.addWidget(scroll)
        self.refresh_favorites()
        return page

    def create_history_page(self):
        page = QWidget(); layout = QVBoxLayout(page); layout.setContentsMargins(10, 10, 10, 10)
        self.history_page = HistoryPage(self.history_manager)
        self.history_page.script_selected.connect(self.open_script_in_injector)
        layout.addWidget(self.history_page)
        return page

    def create_monitor_page(self):
        page = QWidget(); layout = QVBoxLayout(page); layout.setContentsMargins(10, 10, 10, 10)
        self.process_monitor_widget = ProcessMonitorWidget(main_window=self)
        layout.addWidget(self.process_monitor_widget)
        return page

    def create_settings_page(self):
        page = QWidget(); layout = QVBoxLayout(page); layout.setContentsMargins(20, 20, 20, 20); layout.setSpacing(15)
        settings_categories = [
            ("General", [("Auto-inject on launch", "checkbox"), ("Save script history", "checkbox"), ("Dark theme", "checkbox")]),
            ("Script Editor", [("Font size", "spinbox"), ("Show line numbers", "checkbox"), ("Auto-completion", "checkbox")]),
            ("Monitoring", [("Update interval", "spinbox"), ("Show memory usage", "checkbox"), ("Log to file", "checkbox")])
        ]
        for category, settings in settings_categories:
            group = QGroupBox(category); group_layout = QVBoxLayout()
            for setting_name, setting_type in settings:
                setting_layout = QHBoxLayout(); setting_layout.addWidget(QLabel(setting_name))
                widget = QCheckBox() if setting_type == "checkbox" else QSpinBox()
                setting_layout.addWidget(widget); group_layout.addLayout(setting_layout)
            group.setLayout(group_layout); layout.addWidget(group)
        layout.addStretch()
        return page

    # MODIFICATION: This function is heavily modified to route logs
    @pyqtSlot(str, int)
    def handle_injection_request(self, script_content, pid):
        """Unified injection handler for both attaching to a running process and spawning a new one."""
        device = None
        session = None
        
        # Determine if this is an ATTACH or SPAWN operation based on the current state.
        is_attach_mode = self.current_pid is not None and self.current_pid == pid
        is_spawn_mode = self.spawn_target is not None and not is_attach_mode

        try:
            if is_attach_mode:
                # ATTACH workflow for existing processes.
                print(f"[Inject] Handling ATTACH request for PID: {self.current_pid}")
                device_id = self.current_device
                attach_target = self.current_pid
                
                device = frida.get_device(device_id)
                if device.type == 'usb' and not AndroidHelper.is_frida_running(device_id):
                    raise Exception(f"Frida server not running on {device_id}.")
                
                print(f"[Inject] Attaching to PID: {attach_target}...")
                session = device.attach(attach_target)
                self.log_panel.append_output(f"[+] Attached to PID: {attach_target}") # FIX: Log to log_panel

            elif is_spawn_mode:
                # SPAWN workflow for starting new application instances.
                print(f"[Inject] Handling SPAWN request for App: {self.spawn_target}")
                device_id = self.current_device
                app_identifier = self.spawn_target

                device = frida.get_device(device_id)
                if device.type == 'usb' and not AndroidHelper.is_frida_running(device_id):
                    raise Exception(f"Frida server not running on {device_id}.")
                
                print(f"[Inject] Spawning '{app_identifier}'...")
                self.log_panel.append_output(f"[*] Spawning '{app_identifier}'...") # FIX: Log to log_panel
                new_pid = device.spawn([app_identifier])
                
                # Update the main state to reflect the newly spawned process.
                self._update_current_selection(device_id, new_pid)
                
                print(f"[Inject] Attaching to newly spawned PID: {new_pid}...")
                session = device.attach(new_pid)
                self.log_panel.append_output(f"[+] Attached to spawned PID: {new_pid}") # FIX: Log to log_panel
            
            else:
                raise Exception("Injection target mismatch. Re-select the process or app.")
            
            # Common logic for script loading and session handling.
            if not session or session.is_detached:
                raise Exception("Failed to establish a Frida session.")
            
            self.current_session = session
            
            def on_detached(reason, crash):
                if self.current_session is not None:
                    print(f"[Inject] Session detached! Reason: {reason}")
                    self.log_panel.append_output(f"[!] Session detached: {reason}" + (" (App Crashed)" if crash else "")) # FIX: Log to log_panel
                    self.stop_injection(process_ended=crash is not None)
                    if hasattr(self, 'injection_panel'):
                        self.injection_panel.injection_stopped_externally()

            session.on('detached', on_detached)
            
            print("[Inject] Creating script object...")
            script = session.create_script(script_content)
            self.current_script = script
            
            # MODIFICATION: This now correctly routes messages based on type
            def on_message(message, data):
                try:
                    msg_type = message.get('type') if isinstance(message, dict) else 'unknown'
                    
                    if msg_type == 'send':
                        payload = message.get('payload', '')
                        if isinstance(payload, dict):
                            # Handle dict payloads for structured logging (e.g., REPL RESPONSE)
                            log_type = payload.get('type', 'data').upper()
                            log_msg = payload.get('message', str(payload))
                            log_entry = f"[{log_type}] {log_msg}"
                        else:
                            log_entry = f"[SCRIPT SEND] {payload}"
                    elif msg_type == 'log':
                        # This is from console.log()
                        level = message.get('level', 'info').upper()
                        payload = message.get('payload', '')
                        log_entry = f"[CONSOLE.{level}] {payload}"
                    elif msg_type == 'error':
                        # This is from a script error
                        description = message.get('description', 'Unknown Error')
                        stack = message.get('stack', 'No stack trace')
                        log_entry = f"[SCRIPT ERROR] {description}\n{stack}"
                    else:
                        # Other message types (e.g., 'crash', 'rpc')
                        log_entry = f"[{msg_type.upper()}] {message}"
                    
                    if hasattr(self, 'script_output_panel'):
                        self.script_output_panel.append_output(log_entry)

                except Exception as msg_e:
                    if hasattr(self, 'log_panel'):
                        self.log_panel.append_output(f"[APP ERROR] Error processing Frida message: {msg_e}")

            script.on('message', on_message)
            
            print("[Inject] Loading script...")
            script.load()
            print("[Inject] Script loaded.")
            self.log_panel.append_output("[+] Script loaded successfully.") # FIX: Log to log_panel
            
            # If we are in spawn mode, resume the application now that the script is loaded.
            if is_spawn_mode:
                print(f"[Inject] Resuming PID: {self.current_pid}")
                device.resume(self.current_pid)
                self.log_panel.append_output(f"[*] Resumed PID: {self.current_pid}") # FIX: Log to log_panel
            
            if hasattr(self, 'injection_panel'):
                self.injection_panel.injection_succeeded()
            
            self.history_manager.add_entry('script_injection', {
                'script': script_content,
                'pid': self.current_pid, 'device': self.current_device, 'status': 'success'
            })

        except Exception as e:
            error_msg = f"{str(e)}"
            print(f"[Inject] Injection process failed: {error_msg}")
            self.log_panel.append_output(f"[-] Injection Error: {error_msg}") # FIX: Log to log_panel
            if hasattr(self, 'injection_panel'):
                self.injection_panel.injection_failed(error_msg)
            self.stop_injection()
            self.history_manager.add_entry('script_injection', {
                'script': script_content, 'pid': pid, 'device': self.current_device, 'status': 'failed', 'error': error_msg
            })


    def stop_injection(self, process_ended=False):
        """Stop the current injection and clean up state."""
        pid_context = self.current_pid if self.current_pid else "N/A"
        if getattr(self, '_stopping', False): return
        
        if not self.current_script and not self.current_session:
            self._finish_cleanup(pid_context, process_ended)
            return

        self._stopping = True
        self.log_panel.append_output(f"[*] Attempting to stop script for PID: {pid_context}")

        # 1. Create thread and worker
        self.stop_thread = QThread()
        self.stop_worker = StopScriptWorker(
            self.current_script, 
            self.current_session, 
            pid_context, 
            process_ended
        )
        
        # 2. Move worker to thread
        self.stop_worker.moveToThread(self.stop_thread)
        
        # 3. Connect signals for non-blocking cleanup chain
        self.stop_thread.started.connect(self.stop_worker.run)
        self.stop_worker.finished.connect(self._finish_cleanup_from_worker)
        
        # 4. Clean up worker/thread (Crucial for stability)
        self.stop_worker.finished.connect(self.stop_thread.quit)
        self.stop_worker.finished.connect(self.stop_worker.deleteLater)
        self.stop_thread.finished.connect(self.stop_thread.deleteLater)
        
        # Clear main state variables now to avoid race conditions
        self.current_script = None
        self.current_session = None

        # 5. Start thread
        self.stop_thread.start()

    @pyqtSlot(bool, str) 
    def _finish_cleanup_from_worker(self, process_ended, pid_context):
        self._finish_cleanup(pid_context, process_ended)

    def _finish_cleanup(self, pid_context, process_ended):
        # This method is called on the main thread after script stop/detach is complete
        was_running = pid_context != "N/A"
        self.spawn_target = None

        if process_ended:
            self.log_panel.append_output(f"[*] Target process {pid_context} ended.")
            self.current_pid = None
        elif was_running:
            self.log_panel.append_output("[*] Script injection stopped.")

        if hasattr(self, 'injection_panel'):
            self.injection_panel.injection_stopped_update()

        self._update_current_selection(self.current_device, self.current_pid)
        self._stopping = False

        
    # MODIFICATION: New slot to handle worker's completion signal
    @pyqtSlot(bool, str) 
    def _finish_cleanup_from_worker(self, process_ended, pid_context):
        self._finish_cleanup(pid_context, process_ended)


    def _finish_cleanup(self, pid_context, process_ended):
        # This method is called by _finish_cleanup_from_worker on the main thread
        was_running = pid_context != "N/A"
        # self.current_script and self.current_session are already None
        self.spawn_target = None

        if process_ended:
            # FIX: Ensure log targets are correct
            if hasattr(self, 'log_panel'):
                self.log_panel.append_output(f"[*] Target process {pid_context} ended.")
            self.current_pid = None
        elif was_running:
            # FIX: Ensure log targets are correct
            if hasattr(self, 'log_panel'):
                self.log_panel.append_output("[*] Script injection stopped.")

        if hasattr(self, 'injection_panel'):
            self.injection_panel.injection_stopped_update()

        self._update_current_selection(self.current_device, self.current_pid)
        self._stopping = False

    def on_process_selected(self, device_id, pid):
        pass

    def open_in_injector(self, device_id, pid):
        print(f"[MainWindow] Opening Injector for: {pid}@{device_id}")
        self.switch_page('inject')
        if hasattr(self, 'device_selector'):
            self.device_selector.select_device(device_id)
            QTimer.singleShot(100, lambda: self.device_selector.select_process(pid))
        else: print("Error: device_selector not found")

    @pyqtSlot(str)
    def open_script_in_injector(self, code):
        print("[MainWindow] Opening script in injector editor.")
        self.switch_page('inject')
        if hasattr(self, 'script_editor'):
            self.script_editor.set_script(code)
            editor_widget = self.script_editor.get_editor_widget()
            if editor_widget: editor_widget.setFocus()
        else: print("Error: script_editor panel not found")

    # MODIFICATION: New slot to handle messages from the InjectionPanel's REPL
    @pyqtSlot(str)
    def post_message_to_script(self, message):
        """Posts a message from the REPL input to the running script."""
        if self.current_script and self.current_session and not self.current_session.is_detached:
            try:
                # Post a message with type 'input'
                self.current_script.post({'type': 'input', 'payload': message})
                # Log to script output to show what was sent
                self.script_output_panel.append_output(f"[APP -> SCRIPT] {message}")
            except Exception as e:
                self.log_panel.append_output(f"[APP ERROR] Failed to post message: {e}")
        else:
            self.log_panel.append_output("[APP ERROR] Cannot send message: no active script session.")

    @pyqtSlot(bool, str) 
    def _finish_cleanup_from_worker(self, process_ended, pid_context):
        self._finish_cleanup(pid_context, process_ended)

    def _finish_cleanup(self, pid_context, process_ended):
        # This method is called on the main thread after script stop/detach is complete
        was_running = pid_context != "N/A"
        self.spawn_target = None

        if process_ended:
            self.log_panel.append_output(f"[*] Target process {pid_context} ended.")
            self.current_pid = None
        elif was_running:
            self.log_panel.append_output("[*] Script injection stopped.")

        if hasattr(self, 'injection_panel'):
            self.injection_panel.injection_stopped_update()

        self._update_current_selection(self.current_device, self.current_pid)
        self._stopping = False

    def closeEvent(self, event):
        """Handle window close event."""
        self.cleanup()
        event.accept()