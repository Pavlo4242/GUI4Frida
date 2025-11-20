/*
 * Activity Finder Script
 *
 * This script hooks the 'onResume' method of all Activities
 * to show you the class name of the Activity that is
 * currently on screen.
 */

console.log("[*] Starting Activity Finder Script...");

Java.perform(function() {
    
    var Activity = Java.use("android.app.Activity");

    // Hook 'onResume' as it's called every time an Activity
    // comes to the foreground.
    Activity.onResume.implementation = function() {
        var activityName = this.getClass().getName();
        
        var message = "[ACTIVITY] " + activityName;
        
        // Log to console and also send to the GUI
        console.log(message);
        send({ type: "lifecycle", message: message });
        
        // Call the original onResume method
        return this.onResume();
    };

    console.log("[+] Activity.onResume hook installed. Navigate in the app to see activity names.");
});