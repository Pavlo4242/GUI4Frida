Java.perform(function() {
    const TARGET_PACKAGE = "com.grindrapp.android";
    const TRACE_DURATION_MS = 500; // How long to trace for after a click (in milliseconds)

    let tracing = false;
    let hooks = [];

    console.log("[*] Script loaded. Waiting for a screen tap to begin tracing...");
    console.log(`[*] Will trace methods in package '${TARGET_PACKAGE}' for ${TRACE_DURATION_MS}ms after a tap.`);

    // Hook the main touch event dispatcher for all activities
    const Activity = Java.use("android.app.Activity");
    Activity.dispatchTouchEvent.implementation = function(motionEvent) {
        // The MotionEvent object tells us the type of touch event
        const ACTION_DOWN = 0; // The user just pressed the screen

        // We check if the action is ACTION_DOWN and we are not already in the middle of a trace
        if (motionEvent.getAction() === ACTION_DOWN && !tracing) {
            tracing = true;
            console.log("\n\n/* --- CLICK DETECTED: STARTING TRACE --- */");

            // Enumerate all loaded classes and hook methods from our target package
            Java.enumerateLoadedClasses({
                onMatch: function(className) {
                    if (className.startsWith(TARGET_PACKAGE)) {
                        try {
                            const aClass = Java.use(className);
                            const methods = aClass.class.getDeclaredMethods();
                            
                            methods.forEach(function(method) {
                                const methodName = method.getName();
                                // Avoid hooking constructors or very common methods to reduce noise
                                if (methodName === "$init" || methodName === "toString" || methodName === "equals") {
                                    return;
                                }
                                
                                try {
                                    const hook = aClass[methodName].implementation = function() {
                                        // Only log if the trace is active
                                        if (tracing) {
                                            console.log(`// Class:  ${className}`);
                                            console.log(`// Method: ${methodName}`);
                                            console.log('// ----------------------------------------');
                                        }
                                        // Call the original method
                                        return this[methodName].apply(this, arguments);
                                    };
                                    hooks.push(hook); // Store the hook to revert it later
                                } catch (e) {
                                    // Ignore errors from hooking certain methods (e.g., abstract or native)
                                }
                            });
                        } catch (e) {
                            // Ignore
                        }
                    }
                },
                onComplete: function() {}
            });

            // Set a timer to stop the trace and clean up our hooks
            setTimeout(function() {
                console.log("/* --- TRACE COMPLETED: STOPPING TRACE --- */\n");
                // Revert all the hooks we just placed to restore normal execution
                // This is crucial for performance!
                Java.enumerateLoadedClasses({
                    onMatch: function(className) {
                        if (className.startsWith(TARGET_PACKAGE)) {
                            try {
                                const aClass = Java.use(className);
                                const methods = aClass.class.getDeclaredMethods();
                                methods.forEach(function(method) {
                                    try {
                                        aClass[method.getName()].implementation = null;
                                    } catch (e) {}
                                });
                            } catch(e) {}
                        }
                    },
                    onComplete: function() {}
                });
                tracing = false;
            }, TRACE_DURATION_MS);
        }

        // IMPORTANT: Always call the original method to allow the app to function normally
        return this.dispatchTouchEvent.apply(this, arguments);
    };
});