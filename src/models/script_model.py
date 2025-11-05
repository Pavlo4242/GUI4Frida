from PyQt5.QtCore import QObject, pyqtSignal
import os
from datetime import datetime


class ScriptModel(QObject):
    """Model for managing script state"""
    
    script_changed = pyqtSignal(str)  # script content
    script_loaded = pyqtSignal(str, str)  # name, content
    script_saved = pyqtSignal(str)  # file path
    injection_state_changed = pyqtSignal(str)  # state: idle, injecting, running, stopping, stopped
    output_received = pyqtSignal(str, str)  # timestamp, message
    error_occurred = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self._script_content = ""
        self._script_name = ""
        self._injection_state = "idle"
        self._current_session = None
        self._current_scripts = []
        self._output_session_id = None  # Track current output session
        
    @property
    def script_content(self):
        return self._script_content
        
    @property
    def injection_state(self):
        return self._injection_state
        
    @property
    def is_running(self):
        return self._injection_state == "running"
        
    def set_script_content(self, content):
        """Update script content"""
        if content != self._script_content:
            self._script_content = content
            self.script_changed.emit(content)
            
    def load_script(self, file_path):
        """Load script from file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            self._script_content = content
            self._script_name = os.path.basename(file_path)
            self.script_loaded.emit(self._script_name, content)
            self.script_changed.emit(content)
            
        except Exception as e:
            self.error_occurred.emit(f"Failed to load script: {e}")
            
    def save_script(self, file_path, content=None):
        """Save script to file"""
        try:
            content_to_save = content or self._script_content
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content_to_save)
            
            self._script_name = os.path.basename(file_path)
            self.script_saved.emit(file_path)
            
        except Exception as e:
            self.error_occurred.emit(f"Failed to save script: {e}")
            
    def set_injection_state(self, state):
        """Update injection state"""
        valid_states = ["idle", "injecting", "running", "stopping", "stopped"]
        if state in valid_states and state != self._injection_state:
            self._injection_state = state
            self.injection_state_changed.emit(state)
            
            # Start new output session when injecting
            if state == "injecting":
                self._output_session_id = datetime.now().isoformat()
                
    def set_session(self, session, scripts):
        """Set active Frida session and scripts"""
        self._current_session = session
        self._current_scripts = scripts
        
    def clear_session(self):
        """Clear active session"""
        self._current_session = None
        self._current_scripts = []
        
    def add_output(self, message):
        """Add output message with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        self.output_received.emit(timestamp, message)
        
    def get_session_id(self):
        """Get current output session ID"""
        return self._output_session_id
