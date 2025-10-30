from PyQt5.QtWidgets import QWidget, QVBoxLayout, QTextEdit
# Removed unused imports: QFont, Qt

class ScriptEditorPanel(QWidget):
    def __init__(self):
        super().__init__()
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0) # Remove margins if desired

        self.editor = QTextEdit()
        self.editor.setPlaceholderText("Enter your Frida script here...")
        # self.editor.setLineWrap(True) # Removed: Line wrap often not desired for code
        self.editor.setFontFamily("Consolas") # Keep monospace font
        self.editor.setStyleSheet("font-size: 11pt;") # Example: Set font size via stylesheet

        # Set default script template
        self.editor.setPlainText('''Java.perform(function() {
    console.log("Script loaded!");
});''')

        layout.addWidget(self.editor)

    def get_script(self):
        return self.editor.toPlainText()

    def set_script(self, script):
        self.editor.setPlainText(script)

    # Added: Method to clear the editor (called by InjectionPanel)
    def clear(self):
        self.editor.clear()

    # Added: Method to paste into the editor (called by InjectionPanel, if needed)
    def paste(self):
        self.editor.paste()

    # Added: Method to get the actual QTextEdit widget (used by MainWindow)
    def get_editor_widget(self):
        return self.editor