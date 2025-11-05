from PyQt5.QtCore import QObject, pyqtSignal
import json
import os


class SettingsModel(QObject):
    """Model for application settings"""
    
    settings_changed = pyqtSignal(dict)
    setting_changed = pyqtSignal(str, object)  # key, value
    
    def __init__(self, settings_file='frida_data/settings.json'):
        super().__init__()
        self.settings_file = os.path.join(os.getcwd(), settings_file)
        self._settings = self._get_defaults()
        self.load_settings()
        
    def _get_defaults(self):
        """Get default settings"""
        return {
            # General
            'auto_inject_on_launch': False,
            'save_script_history': True,
            'dark_theme': True,
            
            # Script Editor
            'editor_font_size': 15,
            'show_line_numbers': True,
            'auto_completion': False,
            
            # Monitoring
            'update_interval': 3000,  # ms
            'show_memory_usage': False,
            'log_to_file': False,
            
            # UI
            'sidebar_collapsed': False,
            'recent_targets_count': 5,
            'auto_clear_output': True,
            
            # Last Session
            'last_device_id': None,
            'last_process_pid': None,
        }
        
    def get(self, key, default=None):
        """Get setting value"""
        return self._settings.get(key, default)
        
    def set(self, key, value):
        """Set setting value"""
        if key in self._settings and self._settings[key] != value:
            self._settings[key] = value
            self.setting_changed.emit(key, value)
            self.save_settings()
            
    def get_all(self):
        """Get all settings"""
        return self._settings.copy()
        
    def update_multiple(self, settings_dict):
        """Update multiple settings at once"""
        changed = False
        for key, value in settings_dict.items():
            if key in self._settings and self._settings[key] != value:
                self._settings[key] = value
                changed = True
                
        if changed:
            self.settings_changed.emit(self._settings.copy())
            self.save_settings()
            
    def load_settings(self):
        """Load settings from file"""
        try:
            os.makedirs(os.path.dirname(self.settings_file), exist_ok=True)
            
            if os.path.exists(self.settings_file):
                with open(self.settings_file, 'r') as f:
                    loaded = json.load(f)
                    # Merge with defaults to handle new settings
                    self._settings.update(loaded)
                    
        except Exception as e:
            print(f"Error loading settings: {e}")
            
    def save_settings(self):
        """Save settings to file"""
        try:
            os.makedirs(os.path.dirname(self.settings_file), exist_ok=True)
            
            with open(self.settings_file, 'w') as f:
                json.dump(self._settings, f, indent=2)
                
        except Exception as e:
            print(f"Error saving settings: {e}")
            
    def reset_to_defaults(self):
        """Reset all settings to defaults"""
        self._settings = self._get_defaults()
        self.settings_changed.emit(self._settings.copy())
        self.save_settings()