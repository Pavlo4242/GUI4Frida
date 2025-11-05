from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                           QPushButton, QStackedWidget, QLabel, QListWidget, QTableWidget,
                           QGroupBox, QCheckBox, QSpinBox, QMessageBox, QScrollArea,
                           QGridLayout, QLineEdit, QTextEdit, QFrame, QDialog, QFileDialog,
                           QSplitter, QApplication)
from PyQt5.QtCore import Qt, QSize, pyqtSlot, QTimer, QThread, QObject, pyqtSignal
from PyQt5.QtGui import QFont
import qtawesome as qta
from .widgets.device_panel import DevicePanel
from .widgets.process_panel import ProcessPanel
from .widgets.script_editor import ScriptEditorPanel
from .widgets.output_panel import OutputPanel
from .widgets.codeshare_browser import CodeShareBrowser
from .widgets.app_launcher import AppLauncher
from .widgets.process_monitor import ProcessMonitor as ProcessMonitorWidget
from .widgets.injection_panel import InjectionPanel
from .widgets.device_selector import DeviceSelector
from .widgets.history_page import HistoryPage
from core.history_manager import HistoryManager
from core.android_helper import AndroidHelper
from core.script_manager import ScriptManager
import frida
import subprocess
import os
import json
import requests
import sys

SETTINGS_DIR = os.path.join(os.getcwd(), 'frida_data')
FAVORITES_FILE = os.path.join(SETTINGS_DIR, 'favorites.json')

class StopScriptWorker(QObject):
    finished = pyqtSignal(bool, str)

    def __init__(self, scripts, session, pid_context, process_ended=False, parent=None):
        super().__init__(parent)
        self.scripts = scripts
        self.session = session
        self.pid_context = pid_context
        self.process_ended = process_ended

    def run(self):
        for script in self.scripts:
            if script:
                try:
                    script.unload()
                except Exception as e:
                    print(f"[StopScriptWorker] Error unloading script: {e}")
        
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
        self.script_manager = ScriptManager()
        self.favorites = []
        self.load_favorites()
        self.current_device = None
        self.current_pid = None
        self.spawn_target = None
        self.current_session = None
        self.current_scripts = []
        self.pages = {}
        self.setup_ui()
        self.init_pages()
        
        if hasattr(self, 'codeshare_browser'):
            self.codeshare_browser.favorites_updated.connect(self.refresh_favorites)
        
        self.refresh_sidebar_recalls()

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
        
        


    def create_sidebar(self):
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar.setStyleSheet("""
            QWidget#sidebar {
                background-color: #2f3136;
                border-right: 1px solid #202225;
                /* MODIFICATION: Made sidebar wider and removed max-width */
                min-width: 220px;
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

        # MODIFICATION: Moved Recent Actions group before the stretch
        self.scripts_group = QGroupBox("Recent Actions")
        self.scripts_group.setObjectName("RecentActionsGroup")
        self.scripts_group.setStyleSheet("""
            QGroupBox#RecentActionsGroup {
                border: 1px solid #4f545c;
                border-radius: 4px;
                margin-top: 10px;
                padding-top: 15px;
                font-size: 11px;
                color: #b9bbbe;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 3px 0 3px;
            }
            QLabel {
                font-size: 11px;
                color: #96989d;
                padding: 4px;
            }
            QPushButton {
                background-color: #4f545c;
                color: white;
                margin: 2px 4px;
            }
            QPushButton:hover { background-color: #5865f2; }
        """)
        
        scripts_layout = QVBoxLayout(self.scripts_group) 
        scripts_layout.setContentsMargins(5, 10, 5, 5)
        scripts_layout.setSpacing(1)
        # MODIFICATION: Set size policy to allow vertical growth
        self.scripts_group.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)

        layout.addWidget(self.scripts_group)
        layout.addStretch() # MODIFICATION: Stretch is now after recent actions

        status_layout = QHBoxLayout(); status_layout.setContentsMargins(8, 4, 8, 4)
        self.status_icon = QLabel(); self.status_icon.setPixmap(qta.icon('fa5s.circle', color='#43b581').pixmap(8, 8))
        self.status_text = QLabel("Ready"); self.status_text.setStyleSheet("color: #b9bbbe; font-size: 12px;")
        status_layout.addWidget(self.status_icon); status_layout.addWidget(self.status_text)
        layout.addLayout(status_layout)
        return sidebar

        def refresh_sidebar_recalls(self):
             """Refreshes the dynamic content of the sidebar's Recent Actions group."""
        if not hasattr(self, 'scripts_group'): return

        scripts_layout = self.scripts_group.layout()
        while scripts_layout.count() > 0:
            item = scripts_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()

        scripts_layout.addWidget(QLabel("Saved Scripts (2 most recent):"))
        self._add_recent_saved_scripts(scripts_layout)

        scripts_layout.addWidget(QLabel("Recent Injection (History):"))
        self._add_recent_history_script(scripts_layout)


    def _add_recent_saved_scripts(self, layout: QVBoxLayout):
        """Helper to add buttons for the most recently saved scripts."""
        scripts_dir = self.script_manager.scripts_dir
        
        script_files = []
        if os.path.exists(scripts_dir):
            for file_name in os.listdir(scripts_dir):
                if file_name.endswith('.js'):
                    file_path = os.path.join(scripts_dir, file_name)
                    mtime = os.path.getmtime(file_path)
                    script_files.append((file_name, file_path, mtime))

        script_files.sort(key=lambda x: x[2], reverse=True)
        
        found_count = 0
        for name, path, _ in script_files[:2]:
            display_name = os.path.splitext(name)[0] 
            button = QPushButton(qta.icon('fa5s.file-code', color='#7289da'), f" {display_name}")
            button.setCheckable(False)
            button.clicked.connect(lambda checked, p=path: self._load_and_open_script(p)) 
            button.setToolTip(path)
            layout.addWidget(button)
            found_count += 1
            
        if found_count == 0:
            layout.addWidget(QLabel("No saved scripts.").setStyleSheet("margin-left: 5px;"))

    def _add_recent_history_script(self, layout: QVBoxLayout):
        """Helper to add a button for the most recent injected script from history."""
        recent_injections = [
            e for e in self.history_manager.history 
            if e['type'] == 'script_injection' and 'script' in e['details']
        ]
        
        if recent_injections:
            script_content = recent_injections[0]['details']['script']
            
            snippet = script_content.split('\n')[0][:30].strip().replace('"', '').replace("'", "")
            display_name = f"Last: {snippet}..." if len(snippet) > 5 else "Last Injected Script"
            
            button = QPushButton(qta.icon('fa5s.history', color='#faa61a'), f" {display_name}")
            button.setCheckable(False)
            button.clicked.connect(lambda checked, content=script_content: self.open_script_in_injector(content))
            button.setToolTip(f"Re-load script injected at {recent_injections[0]['timestamp']}")
            layout.addWidget(button)
        else:
            layout.addWidget(QLabel("No recent injections.").setStyleSheet("margin-left: 5px;"))

    def _load_and_open_script(self, file_path):
        """Loads script content from a given file path and opens it in the injector."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                script_content = f.read()
            self.open_script_in_injector(script_content)
        except Exception as e:
            QMessageBox.critical(self, "Load Error", f"Failed to load script from disk: {str(e)}")
            self.log_panel.append_output(f"[-] Failed to load script from {file_path}: {e}")

    def init_pages(self):
        self.pages = {
            'home': None, 'inject': None, 'codeshare': None, 
            'favorites': None, 'history': None, 'monitor': None, 'settings': None
        }

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

        initial_page = 'home'
        if initial_page in self.pages and self.pages[initial_page]:
            self.stack.setCurrentWidget(self.pages[initial_page])
            if initial_page in self.nav_buttons:
                self.nav_buttons[initial_page].setChecked(True)
        elif any(self.pages.values()):
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

    def create_injection_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        try:
            self.device_selector = DeviceSelector()
            self.script_editor = ScriptEditorPanel()
            self.injection_panel = InjectionPanel()
            
            
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
            
        self.injection_panel.injection_started.connect(self.handle_injection_request)
        self.injection_panel.injection_stopped.connect(self.stop_injection)
        self.injection_panel.message_posted.connect(self.post_message_to_script)
        self.injection_panel.script_save_requested.connect(self.handle_save_script_request)

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

    def handle_save_script_request(self, name, content):
        """Saves script using ScriptManager, updates history, and provides user feedback."""
        try:
            self.script_manager.save_script(name, content)
            
            script_file_path = os.path.join(self.script_manager.scripts_dir, f"{name}.js")
            
            self.history_manager.add_entry('script_save', {
                'name': f"{name}.js",
                'path': script_file_path,
                'size': len(content),
                'snippet': content[:50] + "..."
            })
            
            QMessageBox.information(self, "Save Success", 
                                    f"Script '{name}.js' saved permanently to:\n{script_file_path}")
                                    
            if hasattr(self.injection_panel, 'save_name_input'):
                self.injection_panel.save_name_input.clear()
            
            # MODIFICATION: Refresh sidebar immediately after saving
            self.refresh_sidebar_recalls()

        except Exception as e:
            QMessageBox.critical(self, "Save Error", f"Failed to save script: {str(e)}")
            self.log_panel.append_output(f"[-] Error saving script: {e}")

    def _update_current_selection(self, device_id, pid):
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

    def _update_spawn_target(self, device_id, app_identifier, script_paths, frida_options):
        self.current_device = device_id
        self.spawn_target = app_identifier
        self.current_pid = None

        status_text = f"Spawn: {self.spawn_target} @ {self.current_device}"
        self.status_text.setText(status_text)
        self.status_icon.setPixmap(qta.icon('fa5s.circle', color='#7289da').pixmap(10, 10))

        print(f"[MainWindow] Spawn Target Set: {app_identifier} on {device_id}")
        print(f"    Scripts: {len(script_paths)}")
        print(f"    Options: {frida_options}")

        self.switch_page('inject')

        self._start_multi_script_spawn(device_id, app_identifier, script_paths, frida_options)

    def _force_stop_application(self, device_id, app_identifier):
        """Force stops the Android application using ADB."""
        cmd = ["adb", "-s", device_id, "shell", "am", "force-stop", app_identifier]
        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            self.log_panel.append_output(f"[*] Force stopped app: {app_identifier}")
            print(f"[Force Stop] Success: {result.stdout.strip()}")
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.strip() if e.stderr else "Unknown ADB error"
            self.log_panel.append_output(f"[-] Failed to force stop: {error_msg}")
            print(f"[Force Stop] Failed: {error_msg}")
            raise Exception(f"Force stop failed: {error_msg}")

    def _start_multi_script_spawn(self, device_id, app_identifier, script_paths, frida_options):
        """Launches app and injects scripts one by one."""
        try:
            device = frida.get_device(device_id)
            if device.type == 'usb' and not AndroidHelper.is_frida_running(device_id):
                raise Exception("Frida server not running on device.")

            self._force_stop_application(device_id, app_identifier)
            
            import time
            time.sleep(0.011)
            self.log_panel.append_output(f"[*] Proceeding with spawn after delay...")

            self.log_panel.append_output(f"[*] Spawning '{app_identifier}'...")
            print(f"[Spawn] Spawning {app_identifier}...")
            pid = device.spawn([app_identifier])

            self._update_current_selection(device_id, pid)
            self.log_panel.append_output(f"[+] Spawned PID: {pid}")

            session = device.attach(pid)
            self.current_session = session

            def on_detached(reason, crash):
                if self.current_session is not None:
                    print(f"[Inject] Session detached! Reason: {reason}")
                    self.log_panel.append_output(f"[!] Session detached: {reason}" + (" (App Crashed)" if crash else "")) 
                    self.stop_injection(process_ended=crash is not None)
                    if hasattr(self, 'injection_panel'):
                        self.injection_panel.injection_stopped_externally()

            session.on('detached', on_detached)

            self.current_scripts = []

            def on_message(message, data):
                try:
                    msg_type = message.get('type') if isinstance(message, dict) else 'unknown'
                    
                    if msg_type == 'send':
                        payload = message.get('payload', '')
                        if isinstance(payload, dict):
                            log_type = payload.get('type', 'data').upper()
                            log_msg = payload.get('message', str(payload))
                            log_entry = f"[{log_type}] {log_msg}"
                        else:
                            log_entry = f"[SCRIPT SEND] {payload}"
                    elif msg_type == 'log':
                        level = message.get('level', 'info').upper()
                        payload = message.get('payload', '')
                        log_entry = f"[CONSOLE.{level}] {payload}"
                    elif msg_type == 'error':
                        description = message.get('description', 'Unknown Error')
                        stack = message.get('stack', 'No stack trace')
                        log_entry = f"[SCRIPT ERROR] {description}\n{stack}"
                    else:
                        log_entry = f"[{msg_type.upper()}] {message}"
                    
                    if hasattr(self, 'script_output_panel'):
                        self.script_output_panel.append_output(log_entry)

                except Exception as msg_e:
                    if hasattr(self, 'log_panel'):
                        self.log_panel.append_output(f"[APP ERROR] Error processing Frida message: {msg_e}")

            for i, script_path in enumerate(script_paths):
                self.log_panel.append_output(f"[*] Loading script {i+1}/{len(script_paths)}: {os.path.basename(script_path)}")
                print(f"  → Loading script {i+1}: {script_path}")

                with open(script_path, 'r', encoding='utf-8') as f:
                    script_content = f.read()

                script = session.create_script(script_content)
                script.on('message', on_message)
                script.load()
                self.current_scripts.append(script)
                self.log_panel.append_output(f"[+] Script {i+1} loaded.")

            print(f"[Spawn] Resuming PID {pid}...")
            device.resume(pid)
            self.log_panel.append_output(f"[*] Resumed PID: {pid}")
            self.log_panel.append_output("[+] All scripts injected and app resumed.")

            if hasattr(self, 'injection_panel'):
                self.injection_panel.injection_succeeded()

        except Exception as e:
            import sys
            ex_type, ex_value, ex_traceback = sys.exc_info()
            error_msg = str(ex_value) if ex_value else "Unknown Spawn Error (No Exception Value)"
            
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

    @pyqtSlot(str, int)
    def handle_injection_request(self, script_content, pid):
        """Unified injection handler for both attaching to a running process and spawning a new one."""
        device = None
        session = None
        
        is_attach_mode = self.current_pid is not None and self.current_pid == pid
        is_spawn_mode = self.spawn_target is not None and not is_attach_mode

        try:
            if is_attach_mode:
                print(f"[Inject] Handling ATTACH request for PID: {self.current_pid}")
                device_id = self.current_device
                attach_target = self.current_pid
                
                device = frida.get_device(device_id)
                if device.type == 'usb' and not AndroidHelper.is_frida_running(device_id):
                    raise Exception(f"Frida server not running on {device_id}.")
                
                print(f"[Inject] Attaching to PID: {attach_target}...")
                session = device.attach(attach_target)
                self.log_panel.append_output(f"[+] Attached to PID: {attach_target}")

            elif is_spawn_mode:
                print(f"[Inject] Handling SPAWN request for App: {self.spawn_target}")
                device_id = self.current_device
                app_identifier = self.spawn_target

                device = frida.get_device(device_id)
                if device.type == 'usb' and not AndroidHelper.is_frida_running(device_id):
                    raise Exception(f"Frida server not running on {device_id}.")
                
                print(f"[Inject] Spawning '{app_identifier}'...")
                self.log_panel.append_output(f"[*] Spawning '{app_identifier}'...")
                new_pid = device.spawn([app_identifier])
                
                self._update_current_selection(device_id, new_pid)
                
                print(f"[Inject] Attaching to newly spawned PID: {new_pid}...")
                session = device.attach(new_pid)
                self.log_panel.append_output(f"[+] Attached to spawned PID: {new_pid}")
            
            else:
                raise Exception("Injection target mismatch. Re-select the process or app.")
            
            if not session or session.is_detached:
                raise Exception("Failed to establish a Frida session.")
            
            self.current_session = session
            
            def on_detached(reason, crash): # -- Unchanged
                if self.current_session is not None:
                    print(f"[Inject] Session detached! Reason: {reason}")
                    self.log_panel.append_output(f"[!] Session detached: {reason}" + (" (App Crashed)" if crash else "")) 
                    self.stop_injection(process_ended=crash is not None)
                    if hasattr(self, 'injection_panel'):
                        self.injection_panel.injection_stopped_externally()

            session.on('detached', on_detached)
            
            print("[Inject] Creating script object...")
            script = session.create_script(script_content)
            self.current_scripts = [script]
            
            def on_message(message, data): # -- Unchanged
                try:
                    msg_type = message.get('type') if isinstance(message, dict) else 'unknown'
                    
                    if msg_type == 'send':
                        payload = message.get('payload', '')
                        if isinstance(payload, dict):
                            log_type = payload.get('type', 'data').upper()
                            log_msg = payload.get('message', str(payload))
                            log_entry = f"[{log_type}] {log_msg}"
                        else:
                            log_entry = f"[SCRIPT SEND] {payload}"
                    elif msg_type == 'log':
                        level = message.get('level', 'info').upper()
                        payload = message.get('payload', '')
                        log_entry = f"[CONSOLE.{level}] {payload}"
                    elif msg_type == 'error':
                        description = message.get('description', 'Unknown Error')
                        stack = message.get('stack', 'No stack trace')
                        log_entry = f"[SCRIPT ERROR] {description}\n{stack}"
                    else:
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
            self.log_panel.append_output("[+] Script loaded successfully.")
            
            if is_spawn_mode:
                print(f"[Inject] Resuming PID: {self.current_pid}")
                device.resume(self.current_pid)
                self.log_panel.append_output(f"[*] Resumed PID: {self.current_pid}")
            
            if hasattr(self, 'injection_panel'):
                self.injection_panel.injection_succeeded()
            
            self.history_manager.add_entry('script_injection', {
                'script': script_content,
                'pid': self.current_pid, 'device': self.current_device, 'status': 'success'
            })
            # MODIFICATION: Refresh sidebar after successful injection
            self.refresh_sidebar_recalls()

        except Exception as e:
            error_msg = f"{str(e)}"
            print(f"[Inject] Injection process failed: {error_msg}")
            self.log_panel.append_output(f"[-] Injection Error: {error_msg}")
            if hasattr(self, 'injection_panel'):
                self.injection_panel.injection_failed(error_msg)
            self.stop_injection()
            self.history_manager.add_entry('script_injection', {
                'script': script_content, 'pid': pid, 'device': self.current_device, 'status': 'failed', 'error': error_msg
            })


    def stop_injection(self, process_ended=False):
        """Stop the current injection and clean up state."""
        pid_context = str(self.current_pid) if self.current_pid else "N/A"
        if getattr(self, '_stopping', False): return
        
        if not self.current_scripts and not self.current_session:
            self._finish_cleanup(pid_context, process_ended)
            return

        self._stopping = True
        self.log_panel.append_output(f"[*] Attempting to stop script for PID: {pid_context}")

        self.stop_thread = QThread()
        self.stop_worker = StopScriptWorker(
            self.current_scripts, 
            self.current_session, 
            pid_context, 
            process_ended
        )
        
        self.stop_worker.moveToThread(self.stop_thread)
        
        self.stop_thread.started.connect(self.stop_worker.run)
        self.stop_worker.finished.connect(self._finish_cleanup_from_worker)
        
        self.stop_worker.finished.connect(self.stop_thread.quit)
        self.stop_worker.finished.connect(self.stop_worker.deleteLater)
        self.stop_thread.finished.connect(self.stop_thread.deleteLater)
        
        self.current_scripts = []
        self.current_session = None

        self.stop_thread.start()

    def _finish_cleanup_from_worker(self, process_ended, pid_context):
        self._finish_cleanup(pid_context, process_ended)

    def _finish_cleanup(self, pid_context, process_ended):
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

    def on_process_selected(self, device_id, pid):
        pass

    def open_in_injector(self, device_id, pid):
        print(f"[MainWindow] Opening Injector for: {pid}@{device_id}")
        self.switch_page('inject')
        if hasattr(self, 'device_selector'):
            self.device_selector.select_device(device_id)
            QTimer.singleShot(100, lambda: self.device_selector.select_process(pid))
        else: print("Error: device_selector not found")

    def open_script_in_injector(self, code):
        print("[MainWindow] Opening script in injector editor.")
        self.switch_page('inject')
        if hasattr(self, 'script_editor'):
            self.script_editor.set_script(code)
            editor_widget = self.script_editor.get_editor_widget()
            if editor_widget: editor_widget.setFocus()
        else: print("Error: script_editor panel not found")

    def post_message_to_script(self, message):
        """Posts a message from the REPL input to the running script."""
        if self.current_scripts and self.current_session and not self.current_session.is_detached:
            try:
                # Post to the last script, assuming it handles REPL
                self.current_scripts[-1].post({'type': 'input', 'payload': message})
                self.script_output_panel.append_output(f"[APP -> SCRIPT] {message}")
            except Exception as e:
                self.log_panel.append_output(f"[APP ERROR] Failed to post message: {e}")
        else:
            self.log_panel.append_output("[APP ERROR] Cannot send message: no active script session.")

    def fetch_scripts(self):
        """Fetch scripts from API"""
        try:
            response = requests.get(self.api_url, timeout=15)
            response.raise_for_status()
            scripts = response.json()
            
            sort_option = self.sort_combo.currentText()
            if sort_option == '★ Most Popular':
                scripts.sort(key=lambda x: x.get('likes', 0), reverse=True)
            elif sort_option == '👁 Most Viewed':
                scripts.sort(key=lambda x: x.get('seen', 0), reverse=True)
            
            return scripts
        except requests.exceptions.RequestException as e:
            print(f"Error fetching scripts (RequestException): {e}")
            QMessageBox.warning(self, "Network Error", f"Failed to fetch CodeShare scripts: {e}. Check internet connection.")
            return []
        except Exception as e:
            print(f"Error fetching scripts: {e}")
            return []

    def refresh_favorites(self):
        """Refresh the favorites grid"""
        for i in reversed(range(self.favorites_grid_layout.count())): 
            widget = self.favorites_grid_layout.itemAt(i).widget()
            if widget:
                widget.setParent(None)
            
        try:
            all_scripts = self.fetch_scripts()
            
            favorite_scripts = [s for s in all_scripts if s['id'] in self.favorites]
            
            if favorite_scripts:
                for idx, script_info in enumerate(favorite_scripts):
                    row = idx // 3
                    col = idx % 3
                    card = self.create_script_card(script_info)
                    self.favorites_grid_layout.addWidget(card, row, col)
            else:
                msg = QLabel("No favorite scripts yet.\nBrowse scripts and click the ★ to add favorites!")
                msg.setAlignment(Qt.AlignCenter)
                msg.setStyleSheet("""
                    color: #b9bbbe;
                    font-size: 14px;
                    padding: 20px;
                """)
                self.favorites_grid_layout.addWidget(msg, 0, 0, 1, 3)
                
        except Exception as e:
            print(f"Error refreshing favorites: {e}")
            error_msg = QLabel(f"Error loading favorites: {str(e)}")
            error_msg.setStyleSheet("color: #ff4444;")
            self.favorites_grid_layout.addWidget(error_msg, 0, 0, 1, 3)

    def filter_favorites(self, text):
        search_text = text.lower()
        layout = getattr(self, 'favorites_grid_layout', None)
        if not layout: return
        no_fav_label = None
        has_visible_card = False
      
        for i in range(layout.count()):
            widget = layout.itemAt(i).widget()
            if widget and isinstance(widget, QFrame):
                labels = widget.findChildren(QLabel)
                title_label = labels[0] if labels else None
                desc_label = labels[2] if len(labels) > 2 else None
 
                if title_label and desc_label:
                     title_matches = search_text in title_label.text().lower()
                     desc_matches = search_text in desc_label.text().lower()
                     is_visible = not search_text or title_matches or desc_matches
    
                     widget.setVisible(is_visible)
                     if is_visible: has_visible_card = True
            elif widget and isinstance(widget, QLabel): 
                no_fav_label = widget
        if no_fav_label: 
            no_fav_label.setVisible(not has_visible_card and not search_text)

    def upload_script(self):
        start_dir = os.getcwd()
        file_path, _ = QFileDialog.getOpenFileName(self, "Upload Script", start_dir, "JavaScript Files (*.js);;All Files (*.*)")
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f: 
                    script_content = f.read()
                script_name = os.path.basename(file_path)
                script_info = {
                    'id': f"custom/{script_name}",
                    'title': script_name,
                    'author': 'Custom Script',
                    'description': 'Uploaded custom script',
                    'likes': 0,
                    'seen': 0,
                    'content': script_content
                }
                self.add_to_favorites(script_info)
            except Exception as e: 
                QMessageBox.critical(self, "Error", f"Failed to upload script: {str(e)}")

    def add_to_favorites(self, script_info):
        if not any(isinstance(s, dict) and s.get('id') == script_info.get('id') for s in self.favorites):
            self.favorites.append(script_info)
            self.save_favorites()
        card = self.create_favorite_card(script_info)
        layout = getattr(self, 'favorites_grid_layout', None)
        if card and layout: 
            count = layout.count()
            row, col = divmod(count, 3)
            layout.addWidget(card, row, col)

    def create_favorite_card(self, script_info):
        card = QFrame()
        card.setStyleSheet("QFrame { background-color: #2f3136; border-radius: 8px; padding: 10px; } QFrame:hover { background-color: #40444b; }")
        layout = QVBoxLayout(card)
        title = QLabel(script_info.get('title', 'N/A'))
        title.setStyleSheet("font-size: 14px; font-weight: bold; color: white;")
        author = QLabel(f"by {script_info.get('author', 'N/A')}")
        author.setStyleSheet("color: #b9bbbe;")
        desc_text = script_info.get('description', '')
        desc = QLabel(desc_text[:100] + ('...' if len(desc_text) > 100 else ''))
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #b9bbbe;")
        buttons = QHBoxLayout()
        view_btn = QPushButton("View")
        view_btn.clicked.connect(lambda checked, si=script_info: self.view_favorite(si))
        inject_btn = QPushButton("Inject")
        inject_btn.clicked.connect(lambda checked, si=script_info: self.open_script_in_injector(si.get('content', '')))
        remove_btn = QPushButton("Remove")
        remove_btn.clicked.connect(lambda checked, si=script_info, c=card: self.remove_from_favorites(si, c))
        buttons.addWidget(view_btn)
        buttons.addWidget(inject_btn)
        buttons.addWidget(remove_btn)
        buttons.addStretch()
        layout.addWidget(title)
        layout.addWidget(author)
        layout.addWidget(desc)
        layout.addLayout(buttons)
        return card

    def view_favorite(self, script_info):
        dialog = QDialog(self)
        dialog.setWindowTitle(f"View Script - {script_info.get('title', 'N/A')}")
        dialog.resize(800, 600)
        layout = QVBoxLayout(dialog)
        content = QTextEdit()
        content.setReadOnly(True)
        try: content.setFont(QFont('Consolas', 15))
        except: pass
        content.setText(script_info.get('content', 'Script content not available'))
        buttons = QHBoxLayout()
        copy_btn = QPushButton(" Copy")
        copy_btn.clicked.connect(lambda: self.copy_to_clipboard(content.toPlainText()))
        inject_btn = QPushButton("Inject")
        inject_btn.clicked.connect(lambda: self.open_script_in_injector(content.toPlainText()))
        buttons.addWidget(copy_btn)
        buttons.addWidget(inject_btn)
        buttons.addStretch()
        layout.addWidget(content)
        layout.addLayout(buttons)
        dialog.exec_()

    def remove_from_favorites(self, script_info, card):
        script_id = script_info.get('id')
        if not script_id: return
        reply = QMessageBox.question(self, "Remove Favorite", f"Remove {script_info.get('title', 'N/A')} from favorites?", QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            card.setParent(None)
            if script_id.startswith('custom/'):
                self.favorites = [s for s in self.favorites if not (isinstance(s, dict) and s.get('id') == script_id)]
                self.save_favorites()
            elif hasattr(self, 'codeshare_browser') and hasattr(self.codeshare_browser, 'favorites'):
                 try: 
                     self.codeshare_browser.favorites.remove(script_id)
                     self.codeshare_browser.save_favorites()
                 except: pass
            self.refresh_favorites()

    def copy_to_clipboard(self, text):
        QApplication.clipboard().setText(text)
        QMessageBox.information(self, "Success", "Copied to clipboard!")

    def cleanup(self):
        """Cleanup resources before closing."""
        if hasattr(self, 'device_selector') and hasattr(self.device_selector, 'cleanup'):
            self.device_selector.cleanup()

    def closeEvent(self, event):
        """Handle window close event."""
        self.cleanup()
        event.accept()