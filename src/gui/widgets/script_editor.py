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
        self.editor.setStyleSheet("font-size: 15pt;")

        # MODIFICATION: Improved default script with better error handling
        self.editor.setPlainText('''Java.perform(function() {
    console.log("[*] Script loaded! Frida REPL is ready.");
    console.log("[*] Type commands in the Send field below and press Enter.");
    
    // REPL Handler - Responds to messages from the host GUI
    recv('input', function(message) {
        console.log("[REPL] Received message:", JSON.stringify(message));
        
        if (!message || !message.payload) {
            console.log("[REPL] Invalid message format");
            return;
        }
        
        var command = message.payload;
        console.log("[REPL] Executing command:", command);
        
        try {
            // Evaluate the command in the global context
            var result = (1, eval)(command);
            
            // Send result back to GUI
            send({
                type: "REPL_RESPONSE", 
                message: "Result: " + JSON.stringify(result)
            });
            
            console.log("[REPL] Command executed successfully");
            
        } catch(e) {
            // Send error back to GUI
            send({
                type: "REPL_ERROR", 
                message: "Error: " + e.message + "\\nStack: " + e.stack
            });
            
            console.log("[REPL] Error:", e.message);
        }
    });
    
    console.log("[*] REPL handler installed successfully");
});''')

        layout.addWidget(self.editor)