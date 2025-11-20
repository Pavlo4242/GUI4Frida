console.log("[*] Starting hook for getPackageInfoNoCheck...");

Java.perform(function() {
    // This is the class where the method lives.
    // If it's not ActivityThread, change this line.
    var ActivityThread = Java.use("android.app.ActivityThread");

    // --- Hook Overload 1 from your error log ---
    try {
        ActivityThread.getPackageInfoNoCheck.overload('android.content.pm.ApplicationInfo', 'android.content.res.CompatibilityInfo')
            .implementation = function(appInfo, compatInfo) {
                
                console.log("[HOOK 1] getPackageInfoNoCheck(appInfo, compatInfo) called");
                
                // --- Your custom logic here ---
                // For example, inspect appInfo.packageName.value

                // Call the original method and return its result
                return this.getPackageInfoNoCheck(appInfo, compatInfo);
            };
        console.log("[+] Hooked overload 1 successfully.");

    } catch (e) {
        console.log("[!] Error hooking overload 1: " + e.message);
    }

    // --- Hook Overload 2 from your error log ---
    try {
        ActivityThread.getPackageInfoNoCheck.overload('android.content.pm.ApplicationInfo', 'android.content.res.CompatibilityInfo', 'boolean')
            .implementation = function(appInfo, compatInfo, someBoolean) {
                
                console.log("[HOOK 2] getPackageInfoNoCheck(appInfo, compatInfo, boolean) called");
                
                // --- Your custom logic here ---

                // Call the original method and return its result
                return this.getPackageInfoNoCheck(appInfo, compatInfo, someBoolean);
            };
        console.log("[+] Hooked overload 2 successfully.");

    } catch (e) {
        console.log("[!] Error hooking overload 2: " + e.message);
    }
});