      console.log("[*] Enumerating classes...");
        
        Java.perform(function() {
            Java.enumerateLoadedClasses({
                onMatch: function(className) {
                    // Filter for Grindr classes
                    if (className.indexOf("com.grindrapp") !== -1 ||
                        className.indexOf("com.grindrplus") !== -1) {
                        
                        send({
                            type: "general",
                            message: "[CLASS] " + className
                        });
                        
                        // Try to get methods
                        try {
                            var clazz = Java.use(className);
                            var methods = clazz.class.getDeclaredMethods();
                            
                            methods.forEach(function(method) {
                                send({
                                    type: "general",
                                    message: "  [METHOD] " + method.getName()
                                });
                            });
                        } catch(e) {}
                    }
                },
                onComplete: function() {
                    console.log("[+] Class enumeration complete");
                }
            });
        });