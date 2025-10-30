      console.log("[*] Installing method tracer...");
        
        // Configure which classes to trace
        var TARGET_CLASSES = [
            "com.grindrapp.android.ui.home.HomeActivity",
            // Add more classes here
        ];
        
        function traceClass(className) {
            try {
                var clazz = Java.use(className);
                var methods = clazz.class.getDeclaredMethods();
                
                methods.forEach(function(method) {
                    var methodName = method.getName();
                    var fullName = className + "." + methodName;
                    
                    try {
                        clazz[methodName].overloads.forEach(function(overload) {
                            overload.implementation = function() {
                                var args = Array.prototype.slice.call(arguments);
                                
                                send({
                                    type: "general",
                                    message: "[TRACE] " + fullName + "(" + args.join(", ") + ")"
                                });
                                
                                var result = this[methodName].apply(this, arguments);
                                
                                send({
                                    type: "general",
                                    message: "[RETURN] " + fullName + " = " + result
                                });
                                
                                return result;
                            };
                        });
                    } catch(e) {}
                });
                
                console.log("[+] Tracing class: " + className);
            } catch(e) {
                console.log("[-] Failed to trace: " + className + " - " + e);
            }
        }
        
        TARGET_CLASSES.forEach(traceClass);
        
        console.log("[+] Method tracer installed");