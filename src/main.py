import sys
from PyQt5.QtWidgets import QApplication
from views.main_window import FridaMainWindow
from utils.themes import set_application_style


def main():
    app = QApplication(sys.argv)
    
    # Apply custom styling
    set_application_style(app)
    
    # Create main window (MVC architecture)
    window = FridaMainWindow()
    window.show()
    
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()