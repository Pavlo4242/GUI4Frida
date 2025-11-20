Java.perform(function() {
    const TARGET_PACKAGE = "com.grindrapp.android.ui.browse";
    const TRACE_DURATION_MS = 500;

    let tracing = false;
    let depth = 0; // For indenting the output to see call hierarchy

    console.log("[*] Script loaded. Ready to perform targeted trace.");
    console.log(`[*] Will focus on classes within '${TARGET_PACKAGE}' package.`);
    console.log("[*] Tap on a profile in the grid to begin the trace.");

    // Function to hook all methods of a specific class
    function traceClass(className) {
        try {
            const aClass = Java.use(className);
            const methods = aClass.class.getDeclaredMethods();
            
            methods.forEach(function(method) {
                const methodName = method.getName();
                if (methodName.includes('$') || methodName === "toString") return; // Skip constructors and noisy methods

                try {
                    aClass[methodName].implementation = function() {
                        if (tracing) {
                            const indent = "  ".repeat(depth);
                            console.log(`${indent}--> ${className}.${methodName}`);
                        }
                        
                        depth++;
                        const result = this[methodName].apply(this, arguments);
                        depth--;
                        
                        if (tracing && depth === 0) {
                             console.log(`  <-- ${className}.${methodName} (returned)`);
                        }
                        return result;
                    };
                } catch (e) { /* Ignore */ }
            });
            console.log(`[+] Successfully prepared hooks for: ${className}`);
        } catch (e) {
             console.log(`[-] Could not hook ${className}: ${e.message}`);
        }
    }
    
    // Main touch event hook to trigger the trace
    const Activity = Java.use("android.app.Activity");
    Activity.dispatchTouchEvent.implementation = function(motionEvent) {
        const ACTION_DOWN = 0;

        if (motionEvent.getAction() === ACTION_DOWN && !tracing) {
            tracing = true;
            depth = 0;
            console.log("\n\n/* --- CLICK DETECTED: STARTING TARGETED TRACE --- */");

            // Enumerate classes to find our targets, especially the ViewModel
            Java.enumerateLoadedClasses({
                onMatch: function(className) {
                    if (className.startsWith(TARGET_PACKAGE)) {
                         // We trace every class in the package based on our last log.
                         // Especially looking for the one that ends with 'ViewModel'
                        if (className.endsWith('ViewModel')) {
                            console.log(`[*] Found a ViewModel, this is a high-value target: ${className}`);
                        }
                        traceClass(className);
                    }
                },
                onComplete: function() {
                    console.log("[*] All relevant classes are now hooked for the next few moments.");
                }
            });

            // Timer to automatically stop the trace and clean up
            setTimeout(function() {g
                console.log("/* --- TRACE COMPLETED --- */\n");
                // Note: For simplicity, this script doesn't unhook. 
                // For a long-running script, you'd need to revert the implementations.
                tracing = false;
            }, TRACE_DURATION_MS);
        }
        return this.dispatchTouchEvent.apply(this, arguments);
    };
});