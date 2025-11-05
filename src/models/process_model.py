from PyQt5.QtCore import QObject, pyqtSignal
from collections import deque
import time


class ProcessModel(QObject):
    """Model for managing processes and process history"""
    
    processes_changed = pyqtSignal(list)  # List of process info dicts
    process_selected = pyqtSignal(str, int)  # device_id, pid
    recent_targets_changed = pyqtSignal(list)  # Recent target history
    error_occurred = pyqtSignal(str)
    
    def __init__(self, max_recent=5):
        super().__init__()
        self._processes = []
        self._current_device_id = None
        self._current_pid = None
        self._current_process_name = None
        self._recent_targets = deque(maxlen=max_recent)
        
    @property
    def current_device_id(self):
        return self._current_device_id
        
    @property
    def current_pid(self):
        return self._current_pid
        
    @property
    def current_process_name(self):
        return self._current_process_name
        
    @property
    def processes(self):
        return self._processes.copy()
        
    @property
    def recent_targets(self):
        return list(self._recent_targets)
        
    def refresh_processes(self, device):
        """Refresh process list from device"""
        try:
            self._processes = []
            processes = device.enumerate_processes()
            
            for process in processes:
                if process.pid > 0 and process.name:
                    self._processes.append({
                        'pid': process.pid,
                        'name': process.name
                    })
            
            # Sort by name
            self._processes.sort(key=lambda p: p['name'].lower())
            self.processes_changed.emit(self._processes)
            
        except Exception as e:
            self.error_occurred.emit(f"Failed to enumerate processes: {e}")
            
    def select_process(self, device_id, pid, name):
        """Select a process"""
        self._current_device_id = device_id
        self._current_pid = pid
        self._current_process_name = name
        
        # Add to recent targets
        self._add_to_recent(device_id, pid, name)
        
        self.process_selected.emit(device_id, pid)
        
    def _add_to_recent(self, device_id, pid, name):
        """Add target to recent history"""
        target = {
            'device_id': device_id,
            'pid': pid,
            'name': name,
            'timestamp': time.time(),
            'is_spawn': pid == 0
        }
        
        # Remove duplicates
        self._recent_targets = deque(
            [t for t in self._recent_targets 
             if not (t['device_id'] == device_id and t['name'] == name and t['pid'] == pid)],
            maxlen=self._recent_targets.maxlen
        )
        
        # Add to front
        self._recent_targets.appendleft(target)
        self.recent_targets_changed.emit(list(self._recent_targets))
        
    def get_process_by_pid(self, pid):
        """Get process info by PID"""
        for proc in self._processes:
            if proc['pid'] == pid:
                return proc
        return None
        
    def clear_selection(self):
        """Clear current process selection"""
        self._current_device_id = None
        self._current_pid = None
        self._current_process_name = None