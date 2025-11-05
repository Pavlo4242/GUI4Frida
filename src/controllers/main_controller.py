from PyQt5.QtCore import QObject
from models import DeviceModel, ProcessModel, ScriptModel, SettingsModel
from controllers.injection_controller import InjectionController
from core.history_manager import HistoryManager
from core.script_manager import ScriptManager


class MainController(QObject):
    def __init__(self):
        super().__init__()
        
        # Step 1: Create all models
        self.settings_model = SettingsModel()
        self.device_model = DeviceModel()
        self.process_model = ProcessModel(
            max_recent=self.settings_model.get('recent_targets_count', 5)
        )
        self.script_model = ScriptModel()
        
        # Step 2: Create managers (legacy code compatibility)
        self.history_manager = HistoryManager()
        self.script_manager = ScriptManager()
        
        # Step 3: Create specialized controllers
        self.injection_controller = InjectionController(
            self.device_model,
            self.process_model,
            self.script_model
        )
        
        # Step 4: Wire up cross-model signals
        self._connect_signals()
        
        # Step 5: Load initial state
        self._restore_last_session()
        
    def _connect_signals(self):
        """Connect signals between models and controllers"""
        # Device selection triggers process refresh
        self.device_model.device_selected.connect(self._on_device_selected)
        
        # Process selection updates injection readiness
        self.process_model.process_selected.connect(self._on_process_selected)
        
        # Script state changes update history
        self.script_model.injection_state_changed.connect(self._on_injection_state_changed)
        
        # Injection success/failure logging
        self.injection_controller.injection_succeeded.connect(self._on_injection_success)
        self.injection_controller.injection_failed.connect(self._on_injection_failed)
        
    def _on_device_selected(self, device_id):
        """Handle device selection"""
        print(f"[MainController] Device selected: {device_id}")
        
        # Refresh processes for new device
        device = self.device_model.get_device(device_id)
        if device:
            self.process_model.refresh_processes(device)
            
    def _on_process_selected(self, device_id, pid):
        """Handle process selection"""
        print(f"[MainController] Process selected: PID {pid} on {device_id}")
        
    def _on_injection_state_changed(self, state):
        """Handle injection state changes"""
        print(f"[MainController] Injection state: {state}")
        
        # Log to history when injection completes
        if state == 'running':
            self.history_manager.add_entry('script_injection', {
                'script': self.script_model.script_content[:100] + "...",
                'pid': self.process_model.current_pid,
                'process_name': self.process_model.current_process_name,
                'device': self.device_model.current_device_id,
                'status': 'success'
            })
            
    def _on_injection_success(self):
        """Handle successful injection"""
        print("[MainController] Injection succeeded")
        
    def _on_injection_failed(self, error):
        """Handle injection failure"""
        print(f"[MainController] Injection failed: {error}")
        
        # Log failure to history
        self.history_manager.add_entry('script_injection', {
            'script': self.script_model.script_content[:100] + "...",
            'pid': self.process_model.current_pid,
            'device': self.device_model.current_device_id,
            'status': 'failed',
            'error': error
        })
        
    def _restore_last_session(self):
        """Restore last session from settings"""
        last_device = self.settings_model.get('last_device_id')
        last_pid = self.settings_model.get('last_process_pid')
        
        if last_device:
            # Try to select last device
            self.device_model.select_device(last_device)
            
    def cleanup(self):
        """Cleanup before shutdown"""
        # Save current session
        self.settings_model.set('last_device_id', self.device_model.current_device_id)
        self.settings_model.set('last_process_pid', self.process_model.current_pid)
        
        # Stop any running injection
        if self.script_model.is_running:
            self.injection_controller.stop_injection()