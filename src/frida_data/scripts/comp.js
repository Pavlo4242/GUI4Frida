ava.perform(function () {
    console.log("? Frida attached on spawn");

    // === 1. Dump all classes related to location/map ===
    Java.enumerateLoadedClasses({
        onMatch: function (className) {
            if (className.toLowerCase().includes("location") || className.toLowerCase().includes("map")) {
                console.log("[Class] Match:", className);
            }
        },
        onComplete: function () {
            console.log("? Class enumeration complete");
        }
    });

    // === 2. Hook all TextView.setText() calls ===
    var TextView = Java.use("android.widget.TextView");
    TextView.setText.overload("java.lang.CharSequence").implementation = function (text) {
        var content = text.toString();
        if (content.toLowerCase().includes("current location")) {
            console.log("[TextView] setText intercepted:", content);
            var gps = "13.7563, 100.5018"; // Bangkok
            console.log("[TextView] Replacing with GPS:", gps);
            return this.setText(gps);
        }
        return this.setText(text);
    };

    // === 3. Hook View.OnClickListener.onClick() ===
    var OnClickListener = Java.use("android.view.View$OnClickListener");
    OnClickListener.onClick.implementation = function (v) {
        try {
            var id = v.getId();
            var context = v.getContext();
            var res = context.getResources();
            var entryName = res.getResourceEntryName(id);
            console.log("[Click] View clicked:", entryName);

            if (entryName.toLowerCase().includes("location")) {
                console.log("[Click] 'Current Location' clicked");
            }
        } catch (e) {
            console.log("[Click] Error:", e);
        }
        return this.onClick(v);
    };

    // === 4. Hook Activity.startActivity(Intent) ===
    var Activity = Java.use("android.app.Activity");
    Activity.startActivity.overload("android.content.Intent").implementation = function (intent) {
        try {
            var action = intent.getAction();
            var data = intent.getData();
            console.log("[Intent] Action:", action);
            if (data) console.log("[Intent] Data:", data.toString());
        } catch (e) {
            console.log("[Intent] Error:", e);
        }
        return this.startActivity(intent);
    };

    // === 5. GPS Spoofing ===
    var Location = Java.use("android.location.Location");
    Location.getLatitude.implementation = function () {
        console.log("[GPS] Spoofed latitude");
        return 13.7563;
    };
    Location.getLongitude.implementation = function () {
        console.log("[GPS] Spoofed longitude");
        return 100.5018;
    };
});