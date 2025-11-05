from PyQt5.QtCore import QObject, pyqtSignal, QThread
import frida
from core.android_helper import AndroidHelper


class StopScriptWorker(QObject):
    """Worker to stop scripts in background thread"""
    finished = pyqtSignal(bool, str)  # process_ended, pid_context

    def __init__(self, scripts, session, pid_context, process_ended=False):
        super().__init__()
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


class InjectionController(QObject):
    """Controller for script injection operations"""
    
    injection_succeeded = pyqtSignal()
    injection_failed = pyqtSignal(str)  # error message
    injection_stopped = pyqtSignal(bool)  # process_ended
    
    def __init__(self, device_model, process_model, script_model):
        super().__init__()
        self.device_model = device_model
        self.process_model = process_model
        self.script_model = script_model
        
        self._stopping = False
        self.stop_thread = None
        self.stop_worker = None
        
    def inject_script(self):
        """Inject current script into selected process"""
        device_id = self.device_model.current_device_id
        pid = self.process_model.current_pid
        script_content = self.script_model.script_content
        
        if not device_id or not pid or not script_content:
            self.injection_failed.emit("Missing device, process, or script content")
            return
            
        try:
            # Update state
            self.script_model.set_injection_state('injecting')
            
            # Get device
            device = frida.get_device(device_id)
            
            # Check Frida server for USB devices
            if device.type == 'usb' and not AndroidHelper.is_frida_running(device_id):
                raise Exception(f"Frida server not running on {device_id}")
            
            # Attach to process
            print(f"[InjectionController] Attaching to PID {pid}...")
            session = device.attach(pid)
            
            # Setup detach handler
            def on_detached(reason, crash):
                print(f"[InjectionController] Session detached: {reason}")
                self.script_model.add_output(f"[!] Session detached: {reason}" + (" (crashed)" if crash else ""))
                self.stop_injection()
                
            session.on('detached', on_detached)
            
            # Create and load script
            print("[InjectionController] Creating script...")
            script = session.create_script(script_content)
            
            # Setup message handler
            def on_message(message, data):
                self._handle_script_message(message, data)
                
            script.on('message', on_message)
            
            print("[InjectionController] Loading script...")
            script.load()
            
            # Store session and scripts
            self.script_model.set_session(session, [script])
            
            # Update state
            self.script_model.set_injection_state('running')
            self.injection_succeeded.emit()
            
            print("[InjectionController] Script injected successfully")
            
        except Exception as e:
            error_msg = str(e)
            print(f"[InjectionController] Injection failed: {error_msg}")
            self.script_model.set_injection_state('idle')
            self.injection_failed.emit(error_msg)
            
    def stop_injection(self):
        """Stop current injection"""
        if self._stopping:
            return
            
        pid_context = str(self.process_model.current_pid) if self.process_model.current_pid else "N/A"
        
        # Get current session/scripts
        session = self.script_model._current_session
        scripts = self.script_model._current_scripts
        
        if not scripts and not session:
            self._finish_cleanup(pid_context, False)
            return
            
        self._stopping = True
        self.script_model.set_injection_state('stopping')
        
        # Create worker thread
        self.stop_thread = QThread()
        self.stop_worker = StopScriptWorker(scripts, session, pid_context, False)
        
        self.stop_worker.moveToThread(self.stop_thread)
        
        self.stop_thread.started.connect(self.stop_worker.run)
        self.stop_worker.finished.connect(self._finish_cleanup_from_worker)
        
        self.stop_worker.finished.connect(self.stop_thread.quit)
        self.stop_worker.finished.connect(self.stop_worker.deleteLater)
        self.stop_thread.finished.connect(self.stop_thread.deleteLater)
        
        # Clear session
        self.script_model.clear_session()
        
        self.stop_thread.start()
        
    def _finish_cleanup_from_worker(self, process_ended, pid_context):
        """Handle cleanup after worker finishes"""
        self._finish_cleanup(pid_context, process_ended)
        
    def _finish_cleanup(self, pid_context, process_ended):
        """Finish cleanup after stop"""
        self.script_model.set_injection_state('stopped')
        self.injection_stopped.emit(process_ended)
        self._stopping = False
        
    def post_message(self, message):
        """Post message to running script"""
        scripts = self.script_model._current_scripts
        session = self.script_model._current_session
        
        if scripts and session and not session.is_detached:
            try:
                scripts[-1].post({'type': 'input', 'payload': message})
                self.script_model.add_output(f"[HOST -> SCRIPT] {message}")
            except Exception as e:
                self.script_model.add_output(f"[ERROR] Failed to post message: {e}")
        else:
            self.script_model.add_output("[ERROR] No active script session")
            
    def _handle_script_message(self, message, data):
        """Handle messages from injected script"""
        try:
            msg_type = message.get('type') if isinstance(message, dict) else 'unknown'
            
            if msg_type == 'send':
                payload = message.get('payload', '')
                if isinstance(payload, dict):
                    log_type = payload.get('type', 'data').upper()
                    log_msg = payload.get('message', str(payload))
                    log_entry = f"[{log_type}] {log_msg}"
                else:
                    log_entry = f"[SCRIPT] {payload}"
            elif msg_type == 'log':
                level = message.get('level', 'info').upper()
                payload = message.get('payload', '')
                log_entry = f"[CONSOLE.{level}] {payload}"
            elif msg_type == 'error':
                description = message.get('description', 'Unknown Error')
                stack = message.get('stack', 'No stack trace')
                log_entry = f"[ERROR] {description}\n{stack}"
            else:
                log_entry = f"[{msg_type.upper()}] {message}"
            
            self.script_model.add_output(log_entry)
            
        except Exception as e:
            self.script_model.add_output(f"[ERROR] Processing message: {e}")