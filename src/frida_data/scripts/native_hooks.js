     console.log("[*] Installing native hooks...");
        
        // Hook fopen
        var fopen = Module.findExportByName(null, "fopen");
        if (fopen) {
            Interceptor.attach(fopen, {
                onEnter: function(args) {
                    var path = Memory.readUtf8String(args[0]);
                    this.path = path;
                    
                    send({
                        type: "general",
                        message: "[native] fopen: " + path
                    });
                    
                    // Block suspicious files
                    if (path.indexOf("goldfish") !== -1 || 
                        path.indexOf("qemu") !== -1) {
                        args[0] = Memory.allocUtf8String("/dev/null");
                        send({
                            type: "detection",
                            message: "[BLOCKED] fopen: " + path
                        });
                    }
                },
                onLeave: function(retval) {
                    if (retval.isNull()) {
                        send({
                            type: "general",
                            message: "[native] fopen failed: " + this.path
                        });
                    }
                }
            });
        }
        
        // Hook system
        var system = Module.findExportByName(null, "system");
        if (system) {
            Interceptor.attach(system, {
                onEnter: function(args) {
                    var cmd = Memory.readUtf8String(args[0]);
                    send({
                        type: "general",
                        message: "[native] system: " + cmd
                    });
                    
                    // Block su commands
                    if (cmd.indexOf("su") !== -1) {
                        args[0] = Memory.allocUtf8String("echo 'blocked'");
                        send({
                            type: "detection",
                            message: "[BLOCKED] system: " + cmd
                        });
                    }
                }
            });
        }
        
        console.log("[+] Native hooks installed");