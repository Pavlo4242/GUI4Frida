from PyQt5.QtCore import QObject, pyqtSignal
import frida
from core.android_helper import AndroidHelper


class DeviceModel(QObject):
    """Model for managing Frida devices"""
    
    devices_changed = pyqtSignal(list)  # List of device info dicts
    device_selected = pyqtSignal(str)   # device_id
    error_occurred = pyqtSignal(str)    # error message
    
    def __init__(self):
        super().__init__()
        self._devices = []
        self._current_device_id = None
        
    @property
    def current_device_id(self):
        return self._current_device_id
        
    @property
    def devices(self):
        return self._devices.copy()
        
    def refresh_devices(self):
        """Enumerate and emit available devices"""
        try:
            self._devices = []
            devices = frida.enumerate_devices()
            
            for device in devices:
                if device.type == 'usb':
                    self._devices.append({
                        'id': device.id,
                        'name': device.name,
                        'type': device.type
                    })
            
            self.devices_changed.emit(self._devices)
            
        except Exception as e:
            self.error_occurred.emit(f"Failed to enumerate devices: {e}")
            
    def select_device(self, device_id):
        """Select a device by ID"""
        if device_id in [d['id'] for d in self._devices]:
            self._current_device_id = device_id
            self.device_selected.emit(device_id)
            return True
        return False
        
    def get_device(self, device_id=None):
        """Get Frida device object"""
        try:
            target_id = device_id or self._current_device_id
            if target_id:
                return frida.get_device(target_id)
        except Exception as e:
            self.error_occurred.emit(f"Failed to get device: {e}")
        return None
        
    def is_frida_running(self, device_id=None):
        """Check if Frida server is running on device"""
        target_id = device_id or self._current_device_id
        if target_id:
            return AndroidHelper.is_frida_running(target_id)
        return False