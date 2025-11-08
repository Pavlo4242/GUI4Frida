/*
 * Emulator Detection Spy Script
 * -----------------------------
 * This script hooks common methods used for emulator detection and logs
 * what the application is looking for. It does *not* bypass detection;
 * it helps you find the specific check that is failing.
 *
 * Run this script and watch the console for messages prefixed with [SPY].
 * Look for suspicious file paths, property keys, or commands.
 */

console.log("[*] Starting comprehensive emulator detection spy...");

Java.perform(function() {
    console.log("[*] Attaching Java hooks...");

    // 1. Hook java.io.File.exists()
    // Apps check for files like "goldfish", "qemu-props", "Genymotion", etc.
    try {
        var File = Java.use("java.io.File");
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            var result = this.exists(); // Call original method

            var suspicious = [
                "qemu", "goldfish", "ranchu", "genymotion", "genymotion", "vbox",
                "bluestacks", "nox", "andy", "ttVM", "android_x86",
                "/dev/socket/qemud", "/dev/qemu_pipe",
                "su", "magisk"
            ];

            for (var i = 0; i < suspicious.length; i++) {
                if (path.toLowerCase().indexOf(suspicious[i]) !== -1) {
                    send({
                        type: "detection",
                        message: "[SPY] File.exists check: " + path + " (Result: " + result + ")"
                    });
                }
            }
            return result;
        };
    } catch (e) {
        console.log("[-] Failed to hook java.io.File: " + e.message);
    }

    // 2. Hook Runtime.exec()
    // Apps try to run commands like "which su"
    try {
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
            send({
                type: "detection",
                message: "[SPY] Runtime.exec check: " + cmd
            });
            return this.exec(cmd);
        };
    } catch (e) {
        console.log("[-] Failed to hook java.lang.Runtime: " + e.message);
    }

    // 3. Hook android.os.SystemProperties.get()
    // This is the MOST common check. Looks for "ro.hardware", "ro.kernel.qemu", etc.
    try {
        var SystemProperties = Java.use("android.os.SystemProperties");
        SystemProperties.get.overload('java.lang.String').implementation = function(key) {
            var value = this.get(key);
            send({
                type: "detection",
                message: "[SPY] SystemProperties.get: " + key + " = " + value
            });
            return value;
        };
        
        SystemProperties.get.overload('java.lang.String', 'java.lang.String').implementation = function(key, def) {
            var value = this.get(key, def);
            send({
                type: "detection",
                message: "[SPY] SystemProperties.get: " + key + " (default: " + def + ") = " + value
            });
            return value;
        };
    } catch (e) {
        console.log("[-] Failed to hook android.os.SystemProperties: " + e.message);
    }

    // 4. Hook android.os.Build fields
    // Apps check static fields like "Build.FINGERPRINT", "Build.HARDWARE", etc.
    try {
        var Build = Java.use("android.os.Build");
        var fields = [
            "MODEL", "FINGERPRINT", "MANUFACTURER", "BRAND",
            "DEVICE", "PRODUCT", "HARDWARE", "SERIAL"
        ];
        
        fields.forEach(function(fieldName) {
            try {
                var field = Build.class.getDeclaredField(fieldName);
                field.setAccessible(true);
                var originalValue = field.get(null);
                send({
                    type: "detection",
                    message: "[SPY] Build." + fieldName + " = " + originalValue
                });
            } catch (e) {
                // Field might not exist on all API levels
            }
        });
    } catch (e) {
        console.log("[-] Failed to hook android.os.Build: " + e.message);
    }

    // 5. Hook PackageManager
    // Apps check for installed packages like "com.bluestacks" or "com.genymotion"
    try {
        var PackageManager = Java.use("android.content.pm.PackageManager");
        PackageManager.getInstalledPackages.overload('int').implementation = function(flags) {
            send({
                type: "detection",
                message: "[SPY] PackageManager.getInstalledPackages() called. App may be scanning for suspicious apps."
            });
            return this.getInstalledPackages(flags);
        };
    } catch (e) {
        console.log("[-] Failed to hook PackageManager: " + e.message);
    }

    console.log("[+] Java hooks attached.");
});

// 6. Hook native functions
// Apps use JNI to call C functions like fopen() to check files.
console.log("[*] Attaching native hooks...");
try {
    var fopen = Module.findExportByName(null, "fopen");
    if (fopen) {
        Interceptor.attach(fopen, {
            onEnter: function(args) {
                var path = Memory.readUtf8String(args[0]);
                if (path) {
                    var suspicious = ["/dev/socket/qemud", "/dev/qemu_pipe", "/system/bin/goldfish", "/system/bin/qemu-props"];
                    for (var i = 0; i < suspicious.length; i++) {
                        if (path.indexOf(suspicious[i]) !== -1) {
                            send({
                                type: "detection",
                                message: "[SPY] Native fopen check: " + path
                            });
                        }
                    }
                }
            }
        });
    }
} catch (e) {
    console.log("[-] Failed to hook native fopen: " + e.message);
}

console.log("[+] All spy hooks installed. Waiting for app to trigger detection...");