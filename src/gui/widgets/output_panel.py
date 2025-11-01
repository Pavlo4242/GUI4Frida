from PyQt5.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QHBoxLayout, QLabel, QPushButton, QFrame
from datetime import datetime
import qtawesome as qta # MODIFICATION: Added qtawesome import

class OutputPanel(QWidget):
    def __init__(self):
        super().__init__()
        self._title = "Output"
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # MODIFICATION: Header/Toolbar for Title and Clear Button
        header_frame = QFrame()
        header_frame.setStyleSheet("""
            QFrame { background-color: #2f3136; border: none; padding: 4px; }
        """)
        header_layout = QHBoxLayout(header_frame)
        header_layout.setContentsMargins(8, 0, 8, 0)
        
        self.title_label = QLabel(self._title)
        self.title_label.setStyleSheet("font-size: 13px; font-weight: bold; color: #dcddde;")

        # MODIFICATION: Clear Button (one button serves the container's output)
        self.clear_btn = QPushButton(qta.icon('fa5s.trash-alt', color='#f04747'), " Clear")
        self.clear_btn.clicked.connect(self.clear_output)
        self.clear_btn.setFlat(True)
        self.clear_btn.setStyleSheet("""
            QPushButton { color: #f04747; padding: 2px 5px; background-color: transparent; border: none; } 
            QPushButton:hover { color: white; }
        """)

        header_layout.addWidget(self.title_label)
        header_layout.addStretch()
        header_layout.addWidget(self.clear_btn)
        
        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        self.output_area.setPlaceholderText("Output will appear here...")
        self.output_area.setStyleSheet("border-top-left-radius: 0px; border-top-right-radius: 0px;")

        layout.addWidget(header_frame)
        layout.addWidget(self.output_area)
    
    # MODIFICATION: New method to allow main window to set the title
    def set_title(self, title):
        self._title = title
        self.title_label.setText(title)

    # ... (append_output and clear_output methods are unchanged)
    def append_output(self, text):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.output_area.append(f"[{timestamp}] {text}")

    def clear_output(self):
        self.output_area.clear()