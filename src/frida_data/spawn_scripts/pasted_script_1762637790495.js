```javascript
/*
 * Frida Script: All-in-One Inspector for GrindrPlus Albums
 *
 * This script investigates two problems simultaneously:
 * 1.  Why are albums still locked? (By spying on the known 'paywall' class)
 * 2.  Why is long-press not working? (By spying on which views get listeners in media activities)
 *
 * Usage: frida -U -f com.grindrapp.android -l inspector_final.js --no-paus
 */

console.log("[+] Starting All-in-One Inspector for Grindr...");

Java.perform(function() {
    const Log = Java.use('java.lang.Throwable'); // For stack traces

    // --- MISSION 1: FIND THE REAL PAYWALL CHECK ---
    // We will hook EVERY method in the paywall class ("Td.d") to see what's being called.
    const paywallClassName = "Td.d";
    try {
        const paywallClass = Java.use(paywallClassName);
        const methods = paywallClass.class.getDeclaredMethods();
        console.log(`[+] Found ${methods.length} methods in ${paywallClassName}. Hooking all of them...`);

        methods.forEach(function(method) {
            const methodName = method.getName();
            const overloadCount = paywallClass[methodName].overloads.length;

            paywallClass[methodName].overloads.forEach(function(overload) {
                overload.implementation = function() {
                    const stack = new Error().stack;
                    // Filter out noise by only showing calls from within the Grindr app itself
                    if (!stack.includes("com.grindrapp.android")) {
                        return overload.apply(this, arguments);
                    }
                    
                    console.log("\n==================== PAYWALL SPY ====================");
                    console.log(`[!] Method called: ${paywallClassName}.${methodName}`);
                    console.log("    -> Arguments: " + Array.from(arguments).join(", "));
                    
                    var retval = overload.apply(this, arguments);
                    
                    console.log("    -> Returned: " + retval);
                    console.log("    -> Stack Trace:\n" + stack.replace(/\n/g, "\n    "));
                    console.log("=====================================================");
                    return retval;
                };
            });
        });
    } catch (e) {
        console.log(`[!] Failed to hook paywall class ${paywallClassName}: ${e.message}`);
    }


    // --- MISSION 2: FIND THE LONG-PRESS TARGET ---
    // We will spy on any attempts to set a long-click listener inside our target media activities.
    const mediaActivities = [
        "com.grindrapp.android.ui.photos.FullScreenExpiringImageActivity",
        "com.grindrapp.android.ui.albums.AlbumsVideoPlayerActivity",
        "com.grindrapp.android.ui.albums.AlbumCruiseActivity",
        "com.grindrapp.android.ui.photos.ChatRoomPhotosActivity"
    ];

    try {
        const View = Java.use('android.view.View');
        View.setOnLongClickListener.implementation = function(listener) {
            const stack = new Error().stack;
            // Check if the listener is being set from within one of our target activities
            if (mediaActivities.some(activityName => stack.includes(activityName))) {
                console.log("\n~~~~~~~~~~~~~~~~~~~ LONG-PRESS SPY ~~~~~~~~~~~~~~~~~~~");
                console.log("[!] setOnLongClickListener was called inside a media activity!");
                console.log("    -> Target View Class: " + this.getClass().getName());
                console.log("    -> Stack Trace:\n" + stack.replace(/\n/g, "\n    "));
                console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            }
            return this.setOnLongClickListener(listener);
        };
        console.log("[+] Hook on setOnLongClickListener is active.");

    } catch(e) {
         console.log(`[!] Failed to hook View.setOnLongClickListener: ${e.message}`);
    }


    // --- BONUS: ACTIVITY SPY ---
    // This will confirm which screen is actually visible.
    try {
        const Activity = Java.use('android.app.Activity');
        Activity.onResume.implementation = function() {
            console.log(`[UI SPY] Activity Resumed: ${this.getClass().getName()}`);
            return this.onResume();
        };
    } catch(e) {}
});