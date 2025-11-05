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
            self.device_model,      # Pass models to controller
            self.process_model,
            self.script_model
        )
        
        # Step 4: Wire up cross-model signals
        self._connect_signals()
        
        # Step 5: Load initial state
        self._restore_last_session()