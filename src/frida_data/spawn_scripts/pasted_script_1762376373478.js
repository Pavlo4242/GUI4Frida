console.log("[+] Starting Final Inspector v2 for Grindr...");

Java.perform(function() {
    const AppConfigClassName = "com.grindrapp.android.platform.config.AppConfiguration";
    var instanceFound = false;

    // --- Helper function for detailed object inspection ---
    function inspectObject(obj, source) {
        if (instanceFound) return; // Only inspect the first one we find
        instanceFound = true;

        console.log("\n\n========================================================");
        console.log("[+] FOUND AppConfiguration INSTANCE via " + source + "!");
        console.log("--------------------------------------------------------");

        try {
            const field_b_object = obj.b.value;
            const field_c_value = obj.c.value;
            const field_z_value = obj.z.value;

            console.log("[*] Field 'b' (Version Name Object): " + field_b_object);
            if (field_b_object) {
                console.log("    - Class: " + field_b_object.$className);
                const b_fields = field_b_object.getClass().getDeclaredFields();
                console.log("    - Inspecting fields of '" + field_b_object.$className + "':");
                b_fields.forEach(function(field) {
                    field.setAccessible(true);
                    console.log("        - " + field.getName() + " (" + field.getType().getName() + "): " + field.get(field_b_object));
                });
            }

            console.log("\n[*] Field 'c' (Version Code): " + field_c_value);
            console.log("\n[*] Field 'z' (Full Version String): " + field_z_value);

        } catch (e) {
            console.log("[!] Error during inspection: " + e);
        }
        console.log("========================================================");
    }

    // --- PRONG 1: Attempt to hook the constructor ---
    try {
        const AppConfigClass = Java.use(AppConfigClassName);
        AppConfigClass.$init.overloads.forEach(function(constructor) {
            constructor.implementation = function() {
                var retval = constructor.apply(this, arguments);
                inspectObject(this, "Constructor Hook");
                return retval;
            };
        });
        console.log("[+] Constructor hook for " + AppConfigClassName + " is active.");
    } catch (err) {
        console.log("[!] Could not hook constructor for " + AppConfigClassName + ". Relying on heap scan. Error: " + err.message);
    }

    // --- PRONG 2: Scan the heap after a delay as a fallback ---
    setTimeout(function() {
        if (instanceFound) return;
        console.log("\n[+] Constructor hook was not hit. Starting heap scan fallback...");
        Java.choose(AppConfigClassName, {
            onMatch: function(instance) {
                console.log("[+] Found an instance of " + AppConfigClassName + " on the heap.");
                inspectObject(instance, "Heap Scan");
                return 'stop'; // Stop searching after we find the first one
            },
            onComplete: function() {
                if (!instanceFound) {
                    console.log("[!] Heap scan complete. No instances of " + AppConfigClassName + " were found.");
                }
            }
        });
    }, 5000); // Wait 5 seconds for the app to initialize before scanning

});