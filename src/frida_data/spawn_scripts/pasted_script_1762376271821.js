console.log("[+] Starting Final Inspector for Grindr...");


Java.perform(function() {
    const AppConfigClassName = "com.grindrapp.android.platform.config.AppConfiguration";
    
    try {
        const AppConfigClass = Java.use(AppConfigClassName);


        // Hook the constructor. We'll hook all overloads just in case.
        AppConfigClass.$init.overloads.forEach(function(constructor) {
            constructor.implementation = function() {
                // Call original constructor
                var retval = constructor.apply(this, arguments);


                console.log("\n\n========================================================");
                console.log("[+] HOOKED AppConfiguration CONSTRUCTOR SUCCESSFULLY!");
                console.log("--------------------------------------------------------");


                try {
                    // Let's inspect the fields that matter 'b', 'c', and 'z'
                    // The '.value' is crucial for accessing fields from a 'this' context in Frida
                    
                    var field_b_object = this.b.value;
                    var field_c_value = this.c.value;
                    var field_z_value = this.z.value;


                    console.log("[*] Field 'b' (Version Name Object): " + field_b_object);
                    console.log("    - Class: " + field_b_object.$className);
                    
                    // Now, let's get the actual string value from inside the 'b' object.
                    // Based on the old code, the inner field might be named 'a' or 'value'.
                    // Let's try to get it and print its methods.
                    try {
                        const b_fields = field_b_object.getClass().getDeclaredFields();
                        console.log("    - Inspecting fields of '" + field_b_object.$className + "':");
                        b_fields.forEach(function(field) {
                            field.setAccessible(true);
                            console.log("        - " + field.getName() + " (" + field.getType().getName() + "): " + field.get(field_b_object));
                        });


                        const b_methods = field_b_object.getClass().getDeclaredMethods();
                        console.log("    - Inspecting methods of '" + field_b_object.$className + "':");
                        b_methods.forEach(function(method) {
                             console.log("        - " + method.getName());
                        });
                        
                    } catch (inner_e) {
                         console.log("    - Could not inspect inner object of field 'b': " + inner_e);
                    }




                    console.log("\n[*] Field 'c' (Version Code): " + field_c_value);
                    console.log("\n[*] Field 'z' (Full Version String): " + field_z_value);


                } catch (e) {
                    console.log("[!] Error during inspection: " + e);
                }


                console.log("========================================================");
                
                return retval;
            };
        });


    } catch (err) {
        console.log("[!] CRITICAL: Failed to find or hook class '" + AppConfigClassName + "'. Error: " + err.message);
    }
});