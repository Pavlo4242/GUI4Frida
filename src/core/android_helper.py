import subprocess
import os
import time
import requests
import platform

class AndroidHelper:
    FRIDA_SERVER_URL = "https://github.com/frida/frida/releases/download/16.1.4/frida-server-16.1.4-android-arm64.xz"
    
    @staticmethod
    def get_adb_path():
        """Get the ADB executable path"""
        if platform.system() == "Windows":
            return "adb.exe"
        return "adb"
        
    @staticmethod
    def is_device_connected(device_id):
        """Check if device is connected"""
        try:
            output = subprocess.check_output([AndroidHelper.get_adb_path(), 'devices'], text=True)
            return device_id in output
        except:
            return False
            
    @staticmethod
    def get_device_arch(device_id):
        """Get device architecture"""
        try:
            output = subprocess.check_output([
                AndroidHelper.get_adb_path(), '-s', device_id, 'shell', 'getprop ro.product.cpu.abi'
            ], text=True).strip()
            
            if 'arm64' in output:
                return 'arm64'
            elif 'arm' in output:
                return 'arm'
            elif 'x86_64' in output:
                return 'x86_64'
            elif 'x86' in output:
                return 'x86'
            return 'arm64'  # Default to arm64
        except:
            return 'arm64'

    @staticmethod
    def start_frida_server(device_id):
        """Start frida-server on device"""
        try:
            adb = AndroidHelper.get_adb_path()
            
            # Get device architecture
            arch = AndroidHelper.get_device_arch(device_id)
            #server_url = f"https://github.com/frida/frida/releases/download/16.1.4/frida-server-16.1.4-android-{arch}.xz"
            server_url = f"https://github.com/frida/frida/releases/download/15.2.2/frida-server-15.2.2-android-{arch}.xz"
            
            # First, try to get root access
            print(f"[ADB] Attempting to gain root access on device {device_id}")
            subprocess.run([adb, '-s', device_id, 'root'], check=True, capture_output=True, text=True)
            time.sleep(1)  # Wait for root to take effect
            
            # Remount system as read-write
            print(f"[ADB] Remounting system as read-write on device {device_id}")
            subprocess.run([adb, '-s', device_id, 'remount'], check=True, capture_output=True, text=True)
            
            # Download and push frida-server (always get fresh copy)
            print(f"Downloading frida-server for {arch}...")
            response = requests.get(server_url, stream=True)
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
            server_path = os.path.join(os.getcwd(), 'frida_data', f'frida-server-{arch}')
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(server_path), exist_ok=True)
            
            # Save and extract
            with open(server_path + '.xz', 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            try:
                print(f"Extracting frida-server archive...")
                subprocess.run(['xz', '-d', '-f', server_path + '.xz'], check=True, capture_output=True, text=True)  # Force extraction
            except subprocess.CalledProcessError as e:
                print(f"Error extracting with xz: {e}. Trying alternative method...")
                import lzma
                try:
                    with lzma.open(server_path + '.xz') as f:
                        with open(server_path, 'wb') as out:
                            out.write(f.read())
                    print("Successfully extracted using lzma.")
                except Exception as e2:
                    print(f"Error extracting with lzma: {e2}.  Failed to extract frida-server.")
                    return False
            
            # Push to device
            print("Pushing frida-server to device...")
            subprocess.run([
                adb, '-s', device_id, 'push',
                server_path, '/data/local/tmp/frida-server'
            ], check=True, capture_output=True, text=True)
            
            # Kill any existing frida-server processes
            print("Killing existing frida-server processes...")
            kill_commands = [
                'pkill -f frida-server',
                'killall -9 frida-server',
                'kill $(pidof frida-server)',
            ]
            
            for cmd in kill_commands:
                try:
                    subprocess.run([adb, '-s', device_id, 'shell', cmd], check=False, capture_output=True, text=True)
                except Exception as e:
                    print(f"Error killing frida-server with command '{cmd}': {e}")
            
            # Set permissions and start server
            start_commands = [
                'chmod 755 /data/local/tmp/frida-server',
                'su -c "chmod 755 /data/local/tmp/frida-server"',
                'su -c "setenforce 0"',
                'su -c "/data/local/tmp/frida-server -D"',  # Run in daemon mode
                '/data/local/tmp/frida-server -D'  # Fallback without su
            ]
            
            for cmd in start_commands:
                try:
                    print(f"Executing command: {cmd}")
                    subprocess.run([adb, '-s', device_id, 'shell', cmd], check=False, capture_output=True, text=True, timeout=5)
                    time.sleep(1)
                    if AndroidHelper.is_frida_running(device_id):
                        print("Frida server started successfully")
                        return True
                except subprocess.TimeoutExpired:
                    print("Timeout while starting frida-server.  Server may be running.")
                    if AndroidHelper.is_frida_running(device_id):
                        print("Frida server started successfully")
                        return True
                except Exception as e:
                    print(f"Error starting frida-server with command '{cmd}': {e}")
                    continue
            
            print("Failed to start frida-server")
            return False
            
        except requests.exceptions.RequestException as e:
            print(f"Error downloading frida-server: {e}")
            return False
        except subprocess.CalledProcessError as e:
            print(f"ADB error: {e.stderr}")
            return False
        except Exception as e:
            print(f"Error starting frida-server: {e}")
            return False

    @staticmethod
    def is_frida_running(device_id):
        """Check if frida-server is running on device"""
        try:
            # Try different ps commands as they vary by Android version
            commands = [
                'ps -A | grep frida-server',
                'ps -ef | grep frida-server',
                'ps | grep frida-server',
                'top -n 1 | grep frida-server',
                'pidof frida-server'
            ]
            
            for cmd in commands:
                try:
                    output = subprocess.check_output(
                        [AndroidHelper.get_adb_path(), '-s', device_id, 'shell', cmd],
                        text=True,
                        stderr=subprocess.PIPE,
                        timeout=2
                    )
                    if ('frida-server' in output and 'grep' not in output) or output.strip().isdigit():
                        return True
                except:
                    continue
            
            # Try netstat as last resort
            try:
                output = subprocess.check_output(
                    [AndroidHelper.get_adb_path(), '-s', device_id, 'shell', 'netstat -tlnp'],
                    text=True,
                    stderr=subprocess.PIPE,
                    timeout=2
                )
                if ':27042' in output:  # Default frida port
                    return True
            except:
                pass
                
            return False
        except:
            return False 