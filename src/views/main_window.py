from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                           QPushButton, QStackedWidget, QFrame, QSplitter,
                           QApplication, QMessageBox)
from PyQt5.QtCore import Qt, QSize, pyqtSlot, QTimer, QPropertyAnimation, QEasingCurve
from PyQt5.QtGui import QFont
import qtawesome as qta
from controllers.main_controller import MainController



from views.injection_view import InjectionView
from views.settings_view import SettingsView
from views.history_view import HistoryView
from gui.widgets.codeshare_browser import CodeShareBrowser
from gui.widgets.process_monitor import ProcessMonitor
import os


class CollapsibleSidebar(QWidget):
    """Collapsible sidebar with smooth animation"""
    
    def __init__(self):
        super().__init__()
        self.is_collapsed = False
        self.nav_buttons = {}
        self.setup_ui()
        
    def setup_ui(self):
        """Setup sidebar UI"""
        self.setObjectName("sidebar")
        self.setStyleSheet("""
            QWidget#sidebar {
                background-color: #2f3136;
                border-right: 1px solid #202225;
            }
            QPushButton {
                text-align: left;
                padding: 10px 12px;
                border: none;
                border-radius: 4px;
                margin: 2px 6px;
                min-height: 36px;
                font-size: 13px;
                color: #b9bbbe;
                background-color: transparent;
            }
            QPushButton:hover {
                background-color: #36393f;
                color: #ffffff;
            }
            QPushButton:checked {
                background-color: #404249;
                color: #ffffff;
            }
        """)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(2)
        layout.setContentsMargins(0, 8, 0, 8)
        
        # Collapse/Expand button
        self.collapse_btn = QPushButton(qta.icon('fa5s.bars', color='#b9bbbe'), "")
        self.collapse_btn.setCheckable(False)
        self.collapse_btn.clicked.connect(self.toggle_collapse)
        self.collapse_btn.setToolTip("Collapse sidebar")
        layout.addWidget(self.collapse_btn)
        
        # Navigation buttons
        nav_items = [
            ("inject", "Script Injection", "fa5s.syringe"),
            ("codeshare", "CodeShare", "fa5s.cloud-download-alt"),
            ("favorites", "Favorites", "fa5s.star"),
            ("history", "History", "fa5s.history"),
            ("monitor", "Process Monitor", "fa5s.desktop"),
            ("settings", "Settings", "fa5s.cog")
        ]
        
        for id_, text, icon in nav_items:
            btn = QPushButton(qta.icon(icon, color='#b9bbbe'), f"  {text}")
            btn.setCheckable(True)
            btn.setProperty("page_id", id_)
            self.nav_buttons[id_] = btn
            layout.addWidget(btn)
            
        layout.addStretch()
        
        # Set initial width
        self.setMinimumWidth(180)
        self.setMaximumWidth(180)
        
    def toggle_collapse(self):
        """Toggle sidebar collapsed state"""
        target_width = 50 if not self.is_collapsed else 180
        
        # Animate width
        self.animation = QPropertyAnimation(self, b"maximumWidth")
        self.animation.setDuration(200)
        self.animation.setStartValue(self.width())
        self.animation.setEndValue(target_width)
        self.animation.setEasingCurve(QEasingCurve.InOutQuad)
        self.animation.start()
        
        # Update button text visibility
        for btn in self.nav_buttons.values():
            if not self.is_collapsed:
                # Collapsing - hide text
                btn.setText("")
            else:
                # Expanding - show text
                page_id = btn.property("page_id")
                text_map = {
                    "inject": "  Script Injection",
                    "codeshare": "  CodeShare",
                    "favorites": "  Favorites",
                    "history": "  History",
                    "monitor": "  Process Monitor",
                    "settings": "  Settings"
                }
                btn.setText(text_map.get(page_id, ""))
                
        self.is_collapsed = not self.is_collapsed
        self.setMinimumWidth(target_width)
        
        # Update tooltip
        self.collapse_btn.setToolTip("Expand sidebar" if self.is_collapsed else "Collapse sidebar")


class FridaMainWindow(QMainWindow):
    """Main application window with MVC architecture"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Frida Script Manager - MVC Architecture")
        self.setMinimumSize(1400, 800)
        
        # Initialize controller (contains all models)
        self.controller = MainController()
        
        # Setup UI
        self.setup_ui()
        
        # Connect signals
        self.connect_signals()
        
        # Initial data load
        self.controller.device_model.refresh_devices()
        
        # Restore sidebar state
        collapsed = self.controller.settings_model.get('sidebar_collapsed', False)
        if collapsed and not self.sidebar.is_collapsed:
            self.sidebar.toggle_collapse()
            
    def setup_ui(self):
        """Setup main window UI"""
        central = QWidget()
        self.setCentralWidget(central)
        
        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Create collapsible sidebar
        self.sidebar = CollapsibleSidebar()
        
        # Create stacked widget for pages
        self.stack = QStackedWidget()
        
        # Create pages
        self.pages = {}
        self.create_pages()
        
        # Add to layout
        layout.addWidget(self.sidebar)
        layout.addWidget(self.stack)
        
        # Connect sidebar buttons
        for page_id, btn in self.sidebar.nav_buttons.items():
            btn.clicked.connect(lambda checked, pid=page_id: self.switch_page(pid))
            
        # Select first page
        if 'inject' in self.sidebar.nav_buttons:
            self.sidebar.nav_buttons['inject'].setChecked(True)
            self.switch_page('inject')
            
    def create_pages(self):
        """Create all pages"""
        # Injection page (main)
        self.pages['inject'] = InjectionView(self.controller)
        self.stack.addWidget(self.pages['inject'])
        
        # CodeShare browser
        self.pages['codeshare'] = CodeShareBrowser()
        self.pages['codeshare'].open_in_injector.connect(self.open_script_in_injector)
        self.stack.addWidget(self.pages['codeshare'])
        
        # Favorites (use CodeShare's favorites tab)
        # We could create a dedicated favorites view or reuse CodeShare
      #  self.pages['favorites'] = self.create_favorites_placeholder()
       # self.stack.addWidget(self.pages['favorites'])
        
        # History
        self.pages['history'] = HistoryView(self.controller.history_manager)
        self.pages['history'].script_selected.connect(self.open_script_in_injector)
        self.stack.addWidget(self.pages['history'])
        
        # Process Monitor
        self.pages['monitor'] = ProcessMonitor(main_window=self)
        if hasattr(self.controller.device_model, 'device_selected'):
            self.controller.device_model.device_selected.connect(
                self.pages['monitor'].on_device_changed
        )
    
        self.stack.addWidget(self.pages['monitor'])
        
        # Settings
        self.pages['settings'] = SettingsView(self.controller.settings_model)
        self.stack.addWidget(self.pages['settings'])
        
    #def create_favorites_placeholder(self):
     #   """Create favorites placeholder page"""
     #   widget = QWidget()
     #   layout = QVBoxLayout(widget)
        
        #label = QLabel("Favorites management coming soon!")
        #label.setAlignment(Qt.AlignCenter)
        #label.setStyleSheet("color: #96989d; font-size: 16px;")
        
        #layout.addStretch()
        #layout.addWidget(label)
        #layout.addStretch()
      #  
       # return widget
        
    def connect_signals(self):

        """Connect controller signals to UI updates"""
        if hasattr(self, 'device_selector') and 'inject' in self.pages:
            from gui.widgets.device_selector import DeviceSelector
            # Find the device selector widget in the injection view
            injection_view = self.pages['inject']
            if hasattr(injection_view, 'findChildren'):
                device_selectors = injection_view.findChildren(DeviceSelector)
                if device_selectors:
                    device_selector = device_selectors[0]
                    device_selector.process_selected.connect(
                        self._on_process_selected_from_selector
                    )
        # Device model signals
        self.controller.device_model.error_occurred.connect(
            lambda msg: QMessageBox.critical(self, "Device Error", msg)
        )
        
        # Process model signals
        self.controller.process_model.error_occurred.connect(
            lambda msg: QMessageBox.warning(self, "Process Error", msg)
        )
        
        # Script model signals
        self.controller.script_model.error_occurred.connect(
            lambda msg: QMessageBox.critical(self, "Script Error", msg)
        )
        
        # Injection controller signals
        self.controller.injection_controller.injection_failed.connect(
            self._on_injection_failed
        )

    def _on_process_selected_from_selector(self, device_id, pid):
        """Handle process selection from device selector widget"""
        if 'inject' in self.pages:
            # Find injection panel and update it
            injection_page = self.pages['inject']
            if hasattr(injection_page, 'findChildren'):
                from gui.widgets.injection_panel import InjectionPanel
                injection_panels = injection_page.findChildren(InjectionPanel)
                if injection_panels:
                    injection_panel = injection_panels[0]
                    injection_panel.set_process(device_id, pid)
                    print(f"[MainWindow] Updated injection panel with PID {pid}")

    def switch_page(self, page_id):
        """Switch to specified page"""
        if page_id not in self.pages:
            return
            
        # Update button states
        for pid, btn in self.sidebar.nav_buttons.items():
            btn.setChecked(pid == page_id)
            
        # Switch page
        self.stack.setCurrentWidget(self.pages[page_id])
        
    def open_script_in_injector(self, script_content):
        """Open script in injection page"""
        # Switch to injection page
        self.switch_page('inject')
        
        # Set script content
        if 'inject' in self.pages:
            self.pages['inject'].script_editor.setPlainText(script_content)
            self.pages['inject'].script_editor.setFocus()
            
    def open_in_injector(self, device_id, pid):
        """Open process in injector (called from Process Monitor)"""
        # Switch to injection page
        self.switch_page('inject')
        
        # Select device and process
        self.controller.device_model.select_device(device_id)
        
        # Wait for processes to refresh, then select
        QTimer.singleShot(300, lambda: self._select_process_delayed(pid))
        
    def _select_process_delayed(self, pid):
        """Select process after delay (to allow refresh)"""
        if 'inject' in self.pages:
            proc = self.controller.process_model.get_process_by_pid(pid)
            if proc:
                self.controller.process_model.select_process(
                    self.controller.device_model.current_device_id,
                    pid,
                    proc['name']
                )
                
    def _on_injection_failed(self, error):
        """Handle injection failure"""
        QMessageBox.critical(
            self,
            "Injection Failed",
            f"Failed to inject script:\n\n{error}"
        )
        
    def closeEvent(self, event):
        """Handle window close"""
        # Save sidebar state
        self.controller.settings_model.set('sidebar_collapsed', self.sidebar.is_collapsed)
        
        # Cleanup
        self.controller.cleanup()
        
        event.accept()