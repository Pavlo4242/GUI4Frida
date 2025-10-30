from PyQt5.QtCore import QObject, pyqtSignal, QTimer
#import psutil
import frida
import weakref

class ProcessMonitor(QObject):
    process_started = pyqtSignal(str, int)  # name, pid
    process_ended = pyqtSignal(str, int)    # name, pid
    # Removed memory_updated signal as psutil is removed
    # memory_updated = pyqtSignal(str, float) # pid, memory_usage
    
    def __init__(self, refresh_rate=2000):
        super().__init__()
        self.refresh_rate = refresh_rate
        self.monitored_processes = {}
        self.timer = QTimer()
        self.timer.timeout.connect(self.check_processes)
        self._stopped = False
        self.device_id = None # Added: Store the ID of the device to monitor
        
    def set_device(self, device_id):
        """Sets the device ID to monitor and resets state."""
        self.device_id = device_id
        # Clear monitored processes when device changes
        self.monitored_processes.clear()
        # Optionally, trigger an immediate check
        self.check_processes()

    def start_monitoring(self):
        self._stopped = False
        # Only start the timer if a device is set, or adjust logic as needed
        if self.device_id:
            self.timer.start(self.refresh_rate)

    def stop_monitoring(self):
        self._stopped = True
        self.timer.stop()
        self.monitored_processes.clear()  # Clear the dictionary
        self.device_id = None # Reset device ID on stop

    
    
    def check_processes(self):
        if self._stopped or not self.device_id: # Modified: Don't run if stopped or no device ID
            return

        current_processes = {}

        try:
            # Modified: Get the specific device using the stored ID
            device = frida.get_device(self.device_id)

            # Ensure the device is still available (e.g., USB connected)
            # Simple check by trying to enumerate processes
            processes = device.enumerate_processes()

            for process in processes:
                if self._stopped:
                    return

                # Only include processes with a valid PID and name
                if process.pid > 0 and process.name:
                    current_processes[process.pid] = process.name

                    # New process detected
                    if process.pid not in self.monitored_processes:
                        self.process_started.emit(process.name, process.pid)

                # Removed memory usage update via psutil, as it's not applicable directly to remote devices
                # try:
                #     p = psutil.Process(process.pid)
                #     memory_mb = p.memory_info().rss / 1024 / 1024
                #     self.memory_updated.emit(str(process.pid), memory_mb)
                # except (psutil.NoSuchProcess, psutil.AccessDenied):
                #     continue

            # Check for ended processes
            ended_pids = list(self.monitored_processes.keys() - current_processes.keys())
            for pid in ended_pids:
                name = self.monitored_processes.get(pid, "Unknown") # Get name safely
                self.process_ended.emit(name, pid)

            self.monitored_processes = current_processes

        except frida.ServerNotRunningError:
             print(f"Frida server not running on device {self.device_id}. Stopping monitor for this device.")
             # Handle case where server stops - maybe emit a signal?
             self.stop_monitoring() # Stop timer if server isn't running
        except frida.TransportError as e:
             print(f"Transport error with device {self.device_id}: {e}. Stopping monitor.")
             # Handle case where device disconnects
             self.stop_monitoring() # Stop timer if device disconnects
        except Exception as e:
            print(f"Error monitoring processes on device {self.device_id}: {str(e)}")
            # Consider stopping or pausing timer on repeated errors

    def __del__(self):
        self.stop_monitoring()