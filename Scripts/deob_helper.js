      console.log("[*] Installing deobfuscation helper...");
        
        var methodCallGraph = {};
        var methodPurposes = {};
        
        // Analyze method behavior
        function analyzeMethod(className, methodName, args, retval) {
            var key = className + "." + methodName;
            
            if (!methodCallGraph[key]) {
                methodCallGraph[key] = {
                    calls: 0,
                    args: [],
                    returns: [],
                    callers: []
                };
            }
            
            methodCallGraph[key].calls++;
            methodCallGraph[key].args.push(JSON.stringify(args));
            methodCallGraph[key].returns.push(JSON.stringify(retval));
            
            // Guess purpose based on behavior
            var purpose = "unknown";
            
            if (methodName.length === 1 || methodName.length === 2) {
                // Likely obfuscated
                if (retval === true || retval === false) {
                    purpose = "detection_check";
                } else if (typeof retval === "string" && retval.startsWith("http")) {
                    purpose = "url_builder";
                } else if (args.length > 0 && typeof args[0] === "string") {
                    if (args[0].indexOf("/") !== -1) {
                        purpose = "file_operation";
                    }
                }
            }
            
            methodPurposes[key] = purpose;
            
            send({
                type: "general",
                message: "[DEOBF] " + key + " purpose: " + purpose + " called " + methodCallGraph[key].calls + " times"
            });
        }
        
        // Hook all single-letter method names (likely obfuscated)
        Java.perform(function() {
            Java.enumerateLoadedClasses({
                onMatch: function(className) {
                    if (className.indexOf("com.grindrapp") !== -1) {
                        try {
                            var clazz = Java.use(className);
                            var methods = clazz.class.getDeclaredMethods();
                            
                            methods.forEach(function(method) {
                                var methodName = method.getName();
                                
                                // Target short method names (obfuscated)
                                if (methodName.length <= 2) {
                                    try {
                                        clazz[methodName].overloads.forEach(function(overload) {
                                            overload.implementation = function() {
                                                var args = Array.prototype.slice.call(arguments);
                                                var retval = this[methodName].apply(this, arguments);
                                                
                                                analyzeMethod(className, methodName, args, retval);
                                                
                                                return retval;
                                            };
                                        });
                                    } catch(e) {}
                                }
                            });
                        } catch(e) {}
                    }
                },
                onComplete: function() {
                    console.log("[+] Deobfuscation helper installed");
                }
            });
        });