```javascript
/*
 * Frida Script - Wide Net Inspector
 *
 * This script casts a wider net to find the version/configuration management class in Grindr.
 * 1. It hooks PackageManager.getPackageInfo to see WHO is asking for version info.
 * 2. It enumerates all loaded classes to find potential candidates for the config class.
 *
 * Usage: frida -U -f com.grindrapp.android -l wide_net_inspector.js --no-paus
 */

console.log("[+] Starting Wide Net Inspector for Grindr...");

Java.perform(function() {
    const Log = Java.use('android.util.Log');
    const Throwable = Java.use('java.lang.Throwable');

    // --- STRATEGY 1: See who is asking for package info ---
    try {
        const PackageManager = Java.use('android.app.ApplicationPackageManager');

        PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(packageName, flags) {
            // We only care when Grindr is inspecting itself.
            if (packageName === 'com.grindrapp.android') {
                const stackTrace = Log.getStackTraceString(Throwable.$new());
                console.log("\n\n=========================================================");
                console.log("[+] PackageManager.getPackageInfo(String, int) was called for Grindr!");
                console.log("    - Stack Trace:\n" + stackTrace);
                console.log("=========================================================\n\n");
            }
            // Call the original method
            return this.getPackageInfo(packageName, flags);
        };
        console.log("[+] Hook on PackageManager.getPackageInfo(String, int) is active.");
    } catch(e) {
        console.log("[!] Failed to hook PackageManager.getPackageInfo(String, int): " + e.message);
    }
    
    // --- STRATEGY 2: Search for interesting class names ---
    console.log("\n[+] Searching for potentially interesting loaded classes...");
    var searchKeywords = ["config", "version", "update", "build", "session"];
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            var lowerClassName = className.toLowerCase();
            if (searchKeywords.some(keyword => lowerClassName.includes(keyword))) {
                 if (className.startsWith("com.grindrapp.android")) {
                    console.log("    -> Found potential class: " + className);
                 }
            }
        },
        onComplete: function() {
            console.log("[+] Class search complete.");
        }
    });
});