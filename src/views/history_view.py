from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                           QLabel, QTableWidget, QTableWidgetItem, QHeaderView,
                           QLineEdit, QComboBox, QMenu, QMessageBox, QApplication)
from PyQt5.QtCore import Qt, pyqtSignal
import qtawesome as qta
from datetime import datetime


class HistoryView(QWidget):
    """Improved history view"""
    
    script_selected = pyqtSignal(str)  # script content
    
    def __init__(self, history_manager):
        super().__init__()
        self.history_manager = history_manager
        self.setup_ui()
        self.refresh_history()
        
    def setup_ui(self):
        """Setup history UI"""
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Header with filters
        header_layout = QHBoxLayout()
        
        title = QLabel("Action History")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: white;")
        
        # Filter by type
        self.type_filter = QComboBox()
        self.type_filter.addItems(['All', 'Script Injection', 'Script Save', 'Spawn'])
        self.type_filter.currentTextChanged.connect(self.apply_filters)
        
        # Search
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search history...")
        self.search_input.textChanged.connect(self.apply_filters)
        self.search_input.setMinimumWidth(200)
        
        # Clear button
        clear_btn = QPushButton(qta.icon('fa5s.trash', color='white'), " Clear History")
        clear_btn.clicked.connect(self.clear_history)
        clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #f04747;
                padding: 6px 12px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #d84040;
            }
        """)
        
        header_layout.addWidget(title)
        header_layout.addStretch()
        header_layout.addWidget(QLabel("Filter:"))
        header_layout.addWidget(self.type_filter)
        header_layout.addWidget(self.search_input)
        header_layout.addWidget(clear_btn)
        
        # History table
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels([
            "Time", "Type", "Target", "Details", "Actions"
        ])
        
        # Style the table
        self.table.setStyleSheet("""
            QTableWidget {
                background-color: #36393f;
                border: none;
                border-radius: 8px;
                gridline-color: #2f3136;
            }
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #2f3136;
            }
            QHeaderView::section {
                background-color: #2f3136;
                padding: 10px;
                border: none;
                color: white;
                font-weight: bold;
            }
        """)
        
        # Set column properties
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)    # Time
        header.setSectionResizeMode(1, QHeaderView.Fixed)    # Type
        header.setSectionResizeMode(2, QHeaderView.Stretch)  # Target
        header.setSectionResizeMode(3, QHeaderView.Stretch)  # Details
        header.setSectionResizeMode(4, QHeaderView.Fixed)    # Actions
        
        self.table.setColumnWidth(0, 150)
        self.table.setColumnWidth(1, 120)
        self.table.setColumnWidth(4, 100)
        
        # Context menu
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        
        # Add to layout
        layout.addLayout(header_layout)
        layout.addWidget(self.table)
        
        # Status
        self.status_label = QLabel()
        self.status_label.setStyleSheet("color: #96989d; font-size: 11px;")
        layout.addWidget(self.status_label)
        
    def refresh_history(self):
        """Refresh history table"""
        self.table.setRowCount(0)
        
        for entry in self.history_manager.history:
            self._add_entry_to_table(entry)
            
        self.update_status()
        
    def _add_entry_to_table(self, entry):
        """Add single entry to table"""
        row = self.table.rowCount()
        self.table.insertRow(row)
        
        # Time
        time_item = QTableWidgetItem(
            datetime.fromisoformat(entry['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
        )
        time_item.setData(Qt.UserRole, entry)  # Store full entry
        
        # Type
        type_map = {
            'script_injection': 'Script Injection',
            'script_save': 'Script Save',
            'spawn': 'App Spawn'
        }
        type_item = QTableWidgetItem(type_map.get(entry['type'], entry['type']))
        
        # Target
        details = entry['details']
        target = "N/A"
        if 'process_name' in details:
            target = f"{details['process_name']} (PID: {details.get('pid', 'N/A')})"
        elif 'name' in details:
            target = details['name']
            
        target_item = QTableWidgetItem(target)
        
        # Details
        detail_text = []
        if entry['type'] == 'script_injection':
            if 'status' in details:
                detail_text.append(f"Status: {details['status']}")
            if 'device' in details:
                detail_text.append(f"Device: {details['device']}")
        elif entry['type'] == 'script_save':
            if 'path' in details:
                detail_text.append(f"Path: {details['path']}")
                
        details_item = QTableWidgetItem(' | '.join(detail_text))
        
        # Add items
        self.table.setItem(row, 0, time_item)
        self.table.setItem(row, 1, type_item)
        self.table.setItem(row, 2, target_item)
        self.table.setItem(row, 3, details_item)
        
        # Action button (for script injections)
        if 'script' in details:
            action_widget = QWidget()
            action_layout = QHBoxLayout(action_widget)
            action_layout.setContentsMargins(4, 4, 4, 4)
            
            inject_btn = QPushButton(qta.icon('fa5s.syringe', color='white'), "")
            inject_btn.setFixedSize(32, 32)
            inject_btn.setToolTip("Re-inject this script")
            inject_btn.clicked.connect(
                lambda checked, s=details['script']: self.script_selected.emit(s)
            )
            inject_btn.setStyleSheet("""
                QPushButton {
                    background-color: #5865f2;
                    border-radius: 4px;
                }
                QPushButton:hover {
                    background-color: #4752c4;
                }
            """)
            
            action_layout.addWidget(inject_btn)
            action_layout.addStretch()
            
            self.table.setCellWidget(row, 4, action_widget)
            
    def apply_filters(self):
        """Apply search and type filters"""
        search_text = self.search_input.text().lower()
        type_filter = self.type_filter.currentText()
        
        type_map = {
            'Script Injection': 'script_injection',
            'Script Save': 'script_save',
            'Spawn': 'spawn'
        }
        
        for row in range(self.table.rowCount()):
            time_item = self.table.item(row, 0)
            if not time_item:
                continue
                
            entry = time_item.data(Qt.UserRole)
            if not entry:
                continue
                
            show = True
            
            # Type filter
            if type_filter != 'All':
                expected_type = type_map.get(type_filter)
                if entry['type'] != expected_type:
                    show = False
                    
            # Search filter
            if search_text and show:
                searchable = ' '.join([
                    str(self.table.item(row, col).text())
                    for col in range(4)
                    if self.table.item(row, col)
                ]).lower()
                
                if search_text not in searchable:
                    show = False
                    
            self.table.setRowHidden(row, not show)
            
        self.update_status()
        
    def update_status(self):
        """Update status label"""
        visible = sum(1 for row in range(self.table.rowCount()) 
                     if not self.table.isRowHidden(row))
        total = self.table.rowCount()
        
        self.status_label.setText(f"Showing {visible} of {total} entries")
        
    def show_context_menu(self, position):
        """Show context menu"""
        menu = QMenu()
        
        copy_action = menu.addAction(qta.icon('fa5s.copy'), "Copy Details")
        copy_action.triggered.connect(self._copy_details)
        
        if self.table.currentRow() >= 0:
            time_item = self.table.item(self.table.currentRow(), 0)
            if time_item:
                entry = time_item.data(Qt.UserRole)
                if entry and 'script' in entry.get('details', {}):
                    inject_action = menu.addAction(qta.icon('fa5s.syringe'), "Re-inject Script")
                    inject_action.triggered.connect(
                        lambda: self.script_selected.emit(entry['details']['script'])
                    )
                    
        menu.exec_(self.table.viewport().mapToGlobal(position))
        
    def _copy_details(self):
        """Copy current row details to clipboard"""
        row = self.table.currentRow()
        if row >= 0:
            time_item = self.table.item(row, 0)
            if time_item:
                entry = time_item.data(Qt.UserRole)
                if entry:
                    clipboard_text = f"Time: {entry['timestamp']}\n"
                    clipboard_text += f"Type: {entry['type']}\n"
                    clipboard_text += f"Details:\n"
                    
                    for key, value in entry['details'].items():
                        if key != 'script' or len(str(value)) < 200:
                            clipboard_text += f"  {key}: {value}\n"
                            
                    QApplication.clipboard().setText(clipboard_text)
                    
    def clear_history(self):
        """Clear all history"""
        reply = QMessageBox.question(
            self,
            "Clear History",
            "Are you sure you want to clear all history?\nThis cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.history_manager.clear_history()
            self.refresh_history()