import sys
from PyQt5.QtWidgets import QApplication
from views.main_window import FridaMainWindow
from utils.themes import set_application_style
from pathlib import Path
# MODIFICATION: Import datetime for timestamped log files
from datetime import datetime
import logging

log_dir = Path("logs")
log_dir.mkdir(exist_ok=True)

# MODIFICATION: Use timestamped file name to create a new log per session and changed extension to .txt
log_file = log_dir / f"session_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"

class LoggerWriter:
    def __init__(self, logger, level):
        self.logger = logger
        self.level = level
    def write(self, message):
        if message.strip():
            self.logger.log(self.level, message.rstrip())
    def flush(self):
        pass

# MODIFICATION: Added %(levelname)s to format for better log readability
# MODIFICATION: Added StreamHandler to keep output in console as well
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler(log_file, encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)

log = logging.getLogger("FullOutput")
# Redirect both stdout and stderr
sys.stdout = LoggerWriter(log, logging.INFO)
sys.stderr = LoggerWriter(log, logging.ERROR)

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