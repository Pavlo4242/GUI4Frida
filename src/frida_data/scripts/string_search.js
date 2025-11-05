     console.log("[*] Searching for strings...");
        
        var TARGET_STRINGS = [
            "emulator", "simulator", "goldfish", "qemu",
            "xposed", "frida", "root", "magisk"
        ];
        
        Java.perform(function() {
            Java.enumerateLoadedClasses({
                onMatch: function(className) {
                    if (className.indexOf("com.grindrapp") !== -1) {
                        try {
                            var clazz = Java.use(className);
                            var fields = clazz.class.getDeclaredFields();
                            
                            fields.forEach(function(field) {
                                try {
                                    field.setAccessible(true);
                                    var value = field.get(null);
                                    
                                    if (value && typeof value === 'string') {
                                        for (var i = 0; i < TARGET_STRINGS.length; i++) {
                                            if (value.toLowerCase().indexOf(TARGET_STRINGS[i]) !== -1) {
                                                send({
                                                    type: "general",
                                                    message: "[STRING_FOUND] " + className + "." + field.getName() + " = " + value
                                                });
                                            }
                                        }
                                    }
                                } catch(e) {}
                            });
                        } catch(e) {}
                    }
                },
                onComplete: function() {
                    console.log("[+] String search complete");
                }
            });
        });