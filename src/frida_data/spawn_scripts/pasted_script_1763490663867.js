Java.perform(function() {
    console.log("[*] Click Tracer loaded. Waiting for a screen tap...");
    const TRACE_DURATION_MS = 400; // Trace for a short period after a tap

    let tracing = false;

    // Hook the main touch event dispatcher
    Java.use("android.app.Activity").dispatchTouchEvent.implementation = function(motionEvent) {
        const ACTION_DOWN = 0; // The user just pressed the screen

        if (motionEvent.getAction() === ACTION_DOWN && !tracing) {
            tracing = true;
            console.log("\n\n/* --- TAP DETECTED: TRACING STARTED --- */");

            Java.enumerateLoadedClasses({
                onMatch: function(className) {
                    if (className.startsWith("com.grindrapp.android.ui")) {
                        try {
                            const aClass = Java.use(className);
                            const methods = aClass.class.getDeclaredMethods();
                            methods.forEach(function(method) {
                                const methodName = method.getName();
                                if (methodName.includes('$')) return; // Skip synthetic methods
                                try {
                                    aClass[methodName].implementation = function() {
                                        if (tracing) {
                                            console.log(`--> ${className}.${methodName}`);
                                        }
                                        return this[methodName].apply(this, arguments);
                                    };
                                } catch (e) {}
                            });
                        } catch (e) {}
                    }
                },
                onComplete: function() {}
            });

            // Timer to stop the trace
            setTimeout(function() {
                console.log("/* --- TRACE COMPLETED --- */\n");
                tracing = false;
                // Note: For simplicity, this doesn't un-hook. Restart the script for a clean trace.
            }, TRACE_DURATION_MS);
        }
        return this.dispatchTouchEvent.apply(this, arguments);
    };
});