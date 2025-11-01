     console.log("[*] Installing comprehensive anti-detection...");
        
        // Block Activity.finish() from detection code
        var Activity = Java.use("android.app.Activity");
        Activity.finish.implementation = function() {
            var stack = Java.use("android.util.Log").getStackTraceString(
                Java.use("java.lang.Exception").$new()
            );
            
            var suspicious = ["Security", "Integrity", "Detection", "Root", "Sift"];
            for (var i = 0; i < suspicious.length; i++) {
                if (stack.indexOf(suspicious[i]) !== -1) {
                    send({
                        type: "detection",
                        message: "[BLOCKED] Activity.finish() from detection code"
                    });
                    return;
                }
            }
            
            return this.finish();
        };
        
        // Hook Debug.isDebuggerConnected
        var Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function() {
            return false;
        };
        
        // Hook PackageManager for Xposed/root app detection
        var PackageManager = Java.use("android.content.pm.PackageManager");
        PackageManager.getInstalledApplications.implementation = function(flags) {
            var apps = this.getInstalledApplications(flags);
            var List = Java.use("java.util.ArrayList");
            var filtered = List.$new();
            
            var suspicious = ["xposed", "magisk", "supersu", "lsposed"];
            
            for (var i = 0; i < apps.size(); i++) {
                var app = apps.get(i);
                var packageName = app.packageName.toLowerCase();
                var isSuspicious = false;
                
                for (var j = 0; j < suspicious.length; j++) {
                    if (packageName.indexOf(suspicious[j]) !== -1) {
                        isSuspicious = true;
                        break;
                    }
                }
                
                if (!isSuspicious) {
                    filtered.add(app);
                }
            }
            
            return filtered;
        };
        
        // Hook Throwable.getStackTrace to hide Frida
        var Throwable = Java.use("java.lang.Throwable");
        Throwable.getStackTrace.implementation = function() {
            var stack = this.getStackTrace();
            var filtered = [];
            
            for (var i = 0; i < stack.length; i++) {
                var frame = stack[i];
                var className = frame.getClassName();
                
                if (className.indexOf("frida") === -1 && 
                    className.indexOf("xposed") === -1) {
                    filtered.push(frame);
                }
            }
            
            return filtered;
        };
        
        // Hook File.exists for all detection files
        var File = Java.use("java.io.File");
        File.exists.implementation = function() {
            var path = this.getAbsolutePath().toLowerCase();
            var result = this.exists();
            
            var suspiciousPaths = [
                "goldfish", "qemu", "genymotion", "vbox", "ttvm",
                "nox", "bluestacks", "xposed", "frida", "magisk",
                "su", "supersu"
            ];
            
            for (var i = 0; i < suspiciousPaths.length; i++) {
                if (path.indexOf(suspiciousPaths[i]) !== -1 && result) {
                    send({
                        type: "detection",
                        message: "[BLOCKED] File: " + this.getAbsolutePath()
                    });
                    return false;
                }
            }
            
            return result;
        };
        
        console.log("[+] Comprehensive anti-detection installed");