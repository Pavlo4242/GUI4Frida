from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
                           QLabel, QCheckBox, QSpinBox, QPushButton, QScrollArea,
                           QFormLayout, QMessageBox, QComboBox)
from PyQt5.QtCore import Qt
import qtawesome as qta


class SettingsView(QWidget):
    """Settings view with working persistence"""
    
    def __init__(self, settings_model):
        super().__init__()
        self.settings_model = settings_model
        self.widgets = {}  # Store widget references
        self.setup_ui()
        self.load_settings()
        
    def setup_ui(self):
        """Setup settings UI"""
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(15)
        
        # Scroll area for settings
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setSpacing(20)
        
        # General Settings
        general_group = self._create_general_settings()
        layout.addWidget(general_group)
        
        # Script Editor Settings
        editor_group = self._create_editor_settings()
        layout.addWidget(editor_group)
        
        # Monitoring Settings
        monitor_group = self._create_monitor_settings()
        layout.addWidget(monitor_group)
        
        # UI Settings
        ui_group = self._create_ui_settings()
        layout.addWidget(ui_group)
        
        layout.addStretch()
        
        scroll.setWidget(container)
        main_layout.addWidget(scroll)
        
        # Bottom buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        
        self.reset_btn = QPushButton(qta.icon('fa5s.undo', color='white'), " Reset to Defaults")
        self.reset_btn.clicked.connect(self._reset_settings)
        self.reset_btn.setStyleSheet("""
            QPushButton {
                background-color: #f04747;
                padding: 8px 16px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #d84040;
            }
        """)
        
        self.save_btn = QPushButton(qta.icon('fa5s.save', color='white'), " Save Settings")
        self.save_btn.clicked.connect(self._save_settings)
        self.save_btn.setStyleSheet("""
            QPushButton {
                background-color: #43b581;
                padding: 8px 16px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #3ca374;
            }
        """)
        
        btn_layout.addWidget(self.reset_btn)
        btn_layout.addWidget(self.save_btn)
        
        main_layout.addLayout(btn_layout)
        
    def _create_general_settings(self):
        """Create general settings group"""
        group = QGroupBox("General")
        group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #40444b;
                border-radius: 8px;
                margin-top: 10px;
                padding: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        
        layout = QFormLayout(group)
        layout.setSpacing(12)
        
        # Auto-inject on launch
        auto_inject = QCheckBox("Automatically inject when process selected")
        self.widgets['auto_inject_on_launch'] = auto_inject
        layout.addRow("Auto-inject:", auto_inject)
        
        # Save script history
        save_history = QCheckBox("Save script execution history")
        self.widgets['save_script_history'] = save_history
        layout.addRow("Save History:", save_history)
        
        # Dark theme (currently always on, but prepared for future)
        dark_theme = QCheckBox("Use dark theme (restart required)")
        dark_theme.setEnabled(False)
        dark_theme.setChecked(True)
        self.widgets['dark_theme'] = dark_theme
        layout.addRow("Theme:", dark_theme)
        
        return group
        
    def _create_editor_settings(self):
        """Create editor settings group"""
        group = QGroupBox("Script Editor")
        group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #40444b;
                border-radius: 8px;
                margin-top: 10px;
                padding: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        
        layout = QFormLayout(group)
        layout.setSpacing(12)
        
        # Font size
        font_size = QSpinBox()
        font_size.setRange(8, 24)
        font_size.setSuffix(" pt")
        self.widgets['editor_font_size'] = font_size
        layout.addRow("Font Size:", font_size)
        
        # Show line numbers
        line_numbers = QCheckBox("Display line numbers in editor")
        self.widgets['show_line_numbers'] = line_numbers
        layout.addRow("Line Numbers:", line_numbers)
        
        # Auto-completion
        auto_complete = QCheckBox("Enable JavaScript auto-completion")
        self.widgets['auto_completion'] = auto_complete
        layout.addRow("Auto-completion:", auto_complete)
        
        return group
        
    def _create_monitor_settings(self):
        """Create monitoring settings group"""
        group = QGroupBox("Process Monitoring")
        group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #40444b;
                border-radius: 8px;
                margin-top: 10px;
                padding: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        
        layout = QFormLayout(group)
        layout.setSpacing(12)
        
        # Update interval
        update_interval = QSpinBox()
        update_interval.setRange(1000, 10000)
        update_interval.setSingleStep(500)
        update_interval.setSuffix(" ms")
        self.widgets['update_interval'] = update_interval
        layout.addRow("Update Interval:", update_interval)
        
        # Show memory usage
        show_memory = QCheckBox("Display memory usage (when available)")
        self.widgets['show_memory_usage'] = show_memory
        layout.addRow("Memory Usage:", show_memory)
        
        # Log to file
        log_to_file = QCheckBox("Save output logs to file")
        self.widgets['log_to_file'] = log_to_file
        layout.addRow("Log to File:", log_to_file)
        
        return group
        
    def _create_ui_settings(self):
        """Create UI settings group"""
        group = QGroupBox("User Interface")
        group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #40444b;
                border-radius: 8px;
                margin-top: 10px;
                padding: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        
        layout = QFormLayout(group)
        layout.setSpacing(12)
        
        # Recent targets count
        recent_count = QSpinBox()
        recent_count.setRange(3, 20)
        recent_count.setSuffix(" targets")
        self.widgets['recent_targets_count'] = recent_count
        layout.addRow("Recent Targets:", recent_count)
        
        # Auto-clear output
        auto_clear = QCheckBox("Auto-clear output on new injection")
        self.widgets['auto_clear_output'] = auto_clear
        layout.addRow("Auto-clear:", auto_clear)
        
        # Sidebar collapsed
        sidebar_collapsed = QCheckBox("Start with sidebar collapsed")
        self.widgets['sidebar_collapsed'] = sidebar_collapsed
        layout.addRow("Sidebar:", sidebar_collapsed)
        
        return group
        
    def load_settings(self):
        """Load settings from model into widgets"""
        settings = self.settings_model.get_all()
        
        for key, widget in self.widgets.items():
            value = settings.get(key)
            if value is not None:
                if isinstance(widget, QCheckBox):
                    widget.setChecked(value)
                elif isinstance(widget, QSpinBox):
                    widget.setValue(value)
                    
    def _save_settings(self):
        """Save settings from widgets to model"""
        new_settings = {}
        
        for key, widget in self.widgets.items():
            if isinstance(widget, QCheckBox):
                new_settings[key] = widget.isChecked()
            elif isinstance(widget, QSpinBox):
                new_settings[key] = widget.value()
                
        self.settings_model.update_multiple(new_settings)
        
        QMessageBox.information(
            self,
            "Settings Saved",
            "Settings have been saved successfully.\nSome changes may require restarting the application."
        )
        
    def _reset_settings(self):
        """Reset settings to defaults"""
        reply = QMessageBox.question(
            self,
            "Reset Settings",
            "Are you sure you want to reset all settings to defaults?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.settings_model.reset_to_defaults()
            self.load_settings()
            QMessageBox.information(self, "Reset Complete", "Settings have been reset to defaults.")
