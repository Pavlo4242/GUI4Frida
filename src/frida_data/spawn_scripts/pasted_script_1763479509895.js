Java.perform(function() {
    const TARGET_STRING = "cascadeClickEvent/position=";
    console.log(`[*] Searching for methods containing the string: "${TARGET_STRING}"`);

    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            // We are interested in the whole app, but can narrow if needed
            if (className.startsWith("com.grindrapp.android")) {
                try {
                    const aClass = Java.use(className);
                    const methods = aClass.class.getDeclaredMethods();
                    
                    methods.forEach(function(method) {
                        const methodBody = method.toString();
                        if (methodBody.includes(TARGET_STRING)) {
                            console.log("\n[!!!] --- MATCH FOUND --- [!!!]");
                            console.log(`[+] Class: ${className}`);
                            console.log(`[+] Method: ${method.getName()}`);
                            console.log("[+] This is the new target for the 'profileTagCascadeFragment' hook.");
                        }
                    });
                } catch (e) { /* Ignore errors */ }
            }
        },
        onComplete: function() {
            console.log("\n[*] String search complete.");
        }
    });
});