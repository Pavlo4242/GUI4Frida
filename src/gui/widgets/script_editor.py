from PyQt5.QtWidgets import QWidget, QVBoxLayout, QTextEdit

class ScriptEditorPanel(QWidget):
    def __init__(self):
        super().__init__()
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.editor = QTextEdit()
        self.editor.setPlaceholderText("Enter your Frida script here...")
        self.editor.setFontFamily("Consolas")
        self.editor.setStyleSheet("font-size: 11pt;")

        # FIX: The self.editor.setPlainText call is now correctly inside a method.
        # This default script includes the functional REPL handler.
        self.editor.setPlainText('''Java.perform(function() {
    console.log("Script loaded! Frida REPL is ready (type in the Send field below).");
    
    // REPL Handler (Responds to messages sent from the host GUI)
    // The host sends: {'type': 'input', 'payload': 'YOUR_COMMAND'}
    recv('input', function(message) {
        if (message && typeof message.payload === 'string') {
            console.log("[REPL_HOST] Executing:", message.payload);
            try {
                // WARNING: Be careful when using eval in a real script.
                var result = eval(message.payload); 
                // Send back the result for display in the GUI
                send({type: "REPL_RESPONSE", message: "Result: " + result});
            } catch(e) {
                send({type: "REPL_ERROR", message: "Error in eval: " + e.message});
            }
        }
    });
});''')

        layout.addWidget(self.editor)

    def get_script(self):
        return self.editor.toPlainText()

    def set_script(self, script):
        self.editor.setPlainText(script)

    def clear(self):
        self.editor.clear()

    def get_editor_widget(self):
        return self.editor