console.log("[+] Starting AppConfiguration Inspector...");

Java.perform(function() {
    const AppConfigClassName = "com.grindrapp.android.platform.config.AppConfiguration";
    const Log = Java.use('android.util.Log');

    /**
     * A helper function to print detailed information about any Java object.
     * It lists the class name, all declared fields with their types and values,
     * and all declared methods.
     */
    function inspectObject(obj, indent) {
        if (!obj) {
            console.log(indent + "Object is null.");
            return;
        }
        const objClass = obj.getClass();
        console.log(indent + "--- Inspecting object of class: " + objClass.getName() + " ---");

        // Inspect Fields
        try {
            const fields = objClass.getDeclaredFields();
            console.log(indent + "  Fields (" + fields.length + "):");
            fields.forEach(function(field) {
                field.setAccessible(true);
                const fieldName = field.getName();
                const fieldType = field.getType().getName();
                const fieldValue = field.get(obj);
                console.log(indent + "    - " + fieldName + " (" + fieldType + "): " + fieldValue);
            });
        } catch (e) {
            console.log(indent + "    Error inspecting fields: " + e.message);
        }

        // Inspect Methods
        try {
            const methods = objClass.getDeclaredMethods();
            console.log(indent + "  Methods (" + methods.length + "):");
            methods.forEach(function(method) {
                console.log(indent + "    - " + method.getName());
            });
        } catch (e) {
            console.log(indent + "    Error inspecting methods: " + e.message);
        }
        console.log(indent + "--- End of Inspection ---");
    }

    try {
        const AppConfigClass = Java.use(AppConfigClassName);

        // Hook all constructors of the AppConfiguration class
        AppConfigClass.$init.overloads.forEach(function(constructor) {
            constructor.implementation = function() {
                // Call the original constructor first to let the object be created
                var retval = constructor.apply(this, arguments);
                
                console.log("\n\n[+] AppConfiguration constructor hooked AFTER execution!");
                console.log("---------------------------------------------------------");

                // Now, inspect the fields of the newly created 'this' object
                try {
                    console.log("Inspecting fields of the final AppConfiguration object:");

                    const field_b = this.b.value;
                    const field_c = this.c.value;
                    const field_z = this.z.value;

                    console.log("\n[FIELD 'b']");
                    console.log("  - Value: " + field_b);
                    console.log("  - Type: " + (field_b ? field_b.$className : "null"));
                    inspectObject(field_b, "    ");

                    console.log("\n[FIELD 'c']");
                    console.log("  - Value: " + field_c);
                    console.log("  - Type: " + (field_c ? field_c.getClass().getName() : "null"));
                    
                    console.log("\n[FIELD 'z']");
                    console.log("  - Value: " + field_z);
                    console.log("  - Type: " + (field_z ? field_z.$className : "null"));


                } catch (e) {
                    console.log("[!] Error inspecting AppConfiguration instance: " + e);
                }
                
                console.log("---------------------------------------------------------");
                return retval;
            };
        });

        console.log("[+] Successfully attached to " + AppConfigClassName + " constructors. Waiting for app to create an instance...");

    } catch (err) {
        console.log("[!] Error attaching to " + AppConfigClassName + ": " + err.message);
    }
});