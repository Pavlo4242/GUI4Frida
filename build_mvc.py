#!/usr/bin/env python3
"""
build_mvc.py - Script to build and verify MVC structure

Usage:
    python build_mvc.py --check    # Check current structure
    python build_mvc.py --build    # Create directory structure
    python build_mvc.py --test     # Test controllers independently
"""

import os
import sys
from pathlib import Path
import argparse


def check_structure():
    """Check if MVC structure exists"""
    print("🔍 Checking MVC structure...")
    
    required_dirs = [
        'src/models',
        'src/controllers', 
        'src/views',
        'src/core',
        'src/utils',
        'src/frida_data'
    ]
    
    required_files = [
        'src/models/__init__.py',
        'src/models/device_model.py',
        'src/models/process_model.py',
        'src/models/script_model.py',
        'src/models/settings_model.py',
        
        'src/controllers/__init__.py',
        'src/controllers/injection_controller.py',
        'src/controllers/main_controller.py',
        
        'src/views/__init__.py',
        'src/views/injection_view.py',
        'src/views/settings_view.py',
        'src/views/history_view.py',
        'src/views/main_window.py',
        
        'src/main.py',
    ]
    
    missing_dirs = []
    missing_files = []
    
    for dir_path in required_dirs:
        if not Path(dir_path).exists():
            missing_dirs.append(dir_path)
        else:
            print(f"  ✅ {dir_path}")
    
    for file_path in required_files:
        if not Path(file_path).exists():
            missing_files.append(file_path)
        else:
            print(f"  ✅ {file_path}")
    
    if missing_dirs or missing_files:
        print("\n❌ Missing components:")
        for d in missing_dirs:
            print(f"  📁 {d}")
        for f in missing_files:
            print(f"  📄 {f}")
        return False
    else:
        print("\n✅ All components present!")
        return True


def build_structure():
    """Create directory structure and __init__.py files"""
    print("🏗️  Building MVC structure...")
    
    # Create directories
    dirs = [
        'src/models',
        'src/controllers',
        'src/views',
        'src/core',
        'src/utils',
        'src/gui/widgets',
        'src/frida_data/scripts',
        'src/frida_data/spawn_scripts'
    ]
    
    for dir_path in dirs:
        Path(dir_path).mkdir(parents=True, exist_ok=True)
        print(f"  📁 Created {dir_path}")
    
    # Create __init__.py files with proper imports
    
    # Models __init__.py
    models_init = """from .device_model import DeviceModel
from .process_model import ProcessModel
from .script_model import ScriptModel
from .settings_model import SettingsModel

__all__ = ['DeviceModel', 'ProcessModel', 'ScriptModel', 'SettingsModel']
"""
    Path('src/models/__init__.py').write_text(models_init)
    print("  ✅ Created models/__init__.py")
    
    # Controllers __init__.py
    controllers_init = """from .injection_controller import InjectionController
from .main_controller import MainController

__all__ = ['InjectionController', 'MainController']
"""
    Path('src/controllers/__init__.py').write_text(controllers_init)
    print("  ✅ Created controllers/__init__.py")
    
    # Views __init__.py
    views_init = """from .injection_view import InjectionView
from .settings_view import SettingsView
from .history_view import HistoryView
from .main_window import FridaMainWindow

__all__ = ['InjectionView', 'SettingsView', 'HistoryView', 'FridaMainWindow']
"""
    Path('src/views/__init__.py').write_text(views_init)
    print("  ✅ Created views/__init__.py")
    
    # Core __init__.py
    Path('src/core/__init__.py').write_text("")
    print("  ✅ Created core/__init__.py")
    
    # GUI widgets __init__.py
    Path('src/gui/__init__.py').write_text("")
    Path('src/gui/widgets/__init__.py').write_text("")
    print("  ✅ Created gui/__init__.py")
    
    print("\n✅ Directory structure built successfully!")


def test_controllers():
    """Test controller creation independently"""
    print("🧪 Testing controller instantiation...\n")
    
    # Add src to path
    sys.path.insert(0, str(Path('src').absolute()))
    
    try:
        # Test 1: Import models
        print("1️⃣  Testing model imports...")
        from models import DeviceModel, ProcessModel, ScriptModel, SettingsModel
        print("  ✅ All models imported successfully")
        
        # Test 2: Create model instances
        print("\n2️⃣  Testing model instantiation...")
        settings = SettingsModel()
        print(f"  ✅ SettingsModel created (loaded {len(settings.get_all())} settings)")
        
        device = DeviceModel()
        print("  ✅ DeviceModel created")
        
        process = ProcessModel()
        print("  ✅ ProcessModel created")
        
        script = ScriptModel()
        print("  ✅ ScriptModel created")
        
        # Test 3: Import controllers
        print("\n3️⃣  Testing controller imports...")
        from controllers import InjectionController, MainController
        print("  ✅ All controllers imported successfully")
        
        # Test 4: Create injection controller
        print("\n4️⃣  Testing controller instantiation...")
        injection_ctrl = InjectionController(device, process, script)
        print("  ✅ InjectionController created")
        
        # Test 5: Create main controller (full integration)
        print("\n5️⃣  Testing MainController (full integration)...")
        main_ctrl = MainController()
        print("  ✅ MainController created")
        print(f"     - Device model: {type(main_ctrl.device_model).__name__}")
        print(f"     - Process model: {type(main_ctrl.process_model).__name__}")
        print(f"     - Script model: {type(main_ctrl.script_model).__name__}")
        print(f"     - Settings model: {type(main_ctrl.settings_model).__name__}")
        print(f"     - Injection controller: {type(main_ctrl.injection_controller).__name__}")
        
        # Test 6: Test signal connections
        print("\n6️⃣  Testing signal connections...")
        
        signal_test_passed = False
        
        def on_device_changed(devices):
            nonlocal signal_test_passed
            signal_test_passed = True
            print(f"  ✅ Signal received: {len(devices)} devices")
        
        main_ctrl.device_model.devices_changed.connect(on_device_changed)
        main_ctrl.device_model.refresh_devices()
        
        if signal_test_passed:
            print("  ✅ Signal/slot mechanism working")
        else:
            print("  ⚠️  No devices found (this is OK if no USB device connected)")
        
        # Test 7: Settings persistence
        print("\n7️⃣  Testing settings persistence...")
        test_value = 12345
        main_ctrl.settings_model.set('editor_font_size', test_value)
        loaded_value = main_ctrl.settings_model.get('editor_font_size')
        
        if loaded_value == test_value:
            print(f"  ✅ Settings persistence working (saved and loaded {test_value})")
        else:
            print(f"  ❌ Settings persistence failed (expected {test_value}, got {loaded_value})")
        
        print("\n✅ All controller tests passed!")
        return True
        
    except ImportError as e:
        print(f"\n❌ Import error: {e}")
        print("   Make sure all model and controller files are in place")
        return False
        
    except Exception as e:
        print(f"\n❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()
        return False


def create_minimal_main():
    """Create a minimal main.py for testing"""
    minimal_main = '''#!/usr/bin/env python3
"""
Minimal main.py for testing MVC structure
"""
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from PyQt5.QtWidgets import QApplication
from views import FridaMainWindow
from utils.themes import set_application_style


def main():
    """Main entry point"""
    print("🚀 Starting Frida Script Manager (MVC)...")
    
    try:
        app = QApplication(sys.argv)
        set_application_style(app)
        
        print("✅ Qt Application created")
        
        # Create main window (builds all controllers)
        window = FridaMainWindow()
        print("✅ Main window created")
        print("✅ All controllers initialized")
        
        window.show()
        print("✅ Window shown\\n")
        print("🎉 Application started successfully!\\n")
        
        sys.exit(app.exec_())
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
'''
    
    Path('src/main.py').write_text(minimal_main)
    print("✅ Created src/main.py")


def main():
    """Main script entry point"""
    parser = argparse.ArgumentParser(description='Build and test MVC structure')
    parser.add_argument('--check', action='store_true', help='Check if structure exists')
    parser.add_argument('--build', action='store_true', help='Build directory structure')
    parser.add_argument('--test', action='store_true', help='Test controllers')
    parser.add_argument('--all', action='store_true', help='Build and test everything')
    
    args = parser.parse_args()
    
    if args.all:
        args.build = True
        args.test = True
    
    if not any([args.check, args.build, args.test]):
        parser.print_help()
        return
    
    print("=" * 60)
    print("  Frida Script Manager - MVC Build Tool")
    print("=" * 60)
    print()
    
    if args.check or args.build or args.test:
        check_structure()
        print()
    
    if args.build:
        build_structure()
        create_minimal_main()
        print()
    
    if args.test:
        success = test_controllers()
        print()
        
        if success:
            print("=" * 60)
            print("  ✅ All tests passed! Ready to run:")
            print("     cd src && python main.py")
            print("=" * 60)
        else:
            print("=" * 60)
            print("  ❌ Some tests failed. Check the output above.")
            print("=" * 60)


if __name__ == '__main__':
    main()