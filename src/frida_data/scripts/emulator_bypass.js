     console.log("[*] Installing emulator detection bypasses...");
        
        // Hook File.exists()
        var File = Java.use("java.io.File");
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            var result = this.exists();
            
            var suspiciousPaths = [
                "goldfish", "qemu", "genymotion", "vbox", "ttVM",
                "nox", "bluestacks", "pipe", "ranchu"
            ];
            
            for (var i = 0; i < suspiciousPaths.length; i++) {
                if (path.toLowerCase().indexOf(suspiciousPaths[i]) !== -1 && result) {
                    send({
                        type: "detection",
                        message: "[BLOCKED] File.exists(): " + path
                    });
                    return false;
                }
            }
            
            return result;
        };
        
        // Hook Build properties
        var Build = Java.use("android.os.Build");
        var BuildClass = Java.use("java.lang.Class").forName("android.os.Build");
        
        // Hook getRadioVersion
        try {
            Build.getRadioVersion.implementation = function() {
                send({
                    type: "detection",
                    message: "[SPOOFED] Build.getRadioVersion() = 1.0.0.0"
                });
                return "1.0.0.0";
            };
        } catch(e) {}
        
        // Hook SystemProperties
        try {
            var SystemProperties = Java.use("android.os.SystemProperties");
            SystemProperties.get.overload('java.lang.String').implementation = function(key) {
                var result = this.get(key);
                
                var emulatorProps = [
                    "ro.kernel.qemu", "ro.hardware", "ro.product.device"
                ];
                
                for (var i = 0; i < emulatorProps.length; i++) {
                    if (key.indexOf(emulatorProps[i]) !== -1) {
                        send({
                            type: "detection",
                            message: "[SPOOFED] SystemProperty: " + key + " = OnePlus7Pro"
                        });
                        
                        if (key.indexOf("qemu") !== -1) return "0";
                        if (key.indexOf("hardware") !== -1) return "qcom";
                        return "OnePlus7Pro";
                    }
                }
                
                return result;
            };
        } catch(e) {
            console.log("[-] Could not hook SystemProperties: " + e);
        }
        
        console.log("[+] Emulator detection bypasses installed");