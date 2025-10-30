      console.log("[*] Installing root detection bypass...");
        
        // Hook Runtime.exec for su checks
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
            if (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1) {
                send({
                    type: "detection",
                    message: "[BLOCKED] Runtime.exec: " + cmd
                });
                throw new Error("Command not found");
            }
            return this.exec(cmd);
        };
        
        // Hook File.exists for su binaries
        var File = Java.use("java.io.File");
        var exists_original = File.exists;
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            
            var suPaths = [
                "/system/bin/su", "/system/xbin/su", "/sbin/su",
                "/data/local/xbin/su", "/data/local/bin/su"
            ];
            
            for (var i = 0; i < suPaths.length; i++) {
                if (path === suPaths[i]) {
                    send({
                        type: "detection",
                        message: "[BLOCKED] File.exists: " + path
                    });
                    return false;
                }
            }
            
            return exists_original.call(this);
        };
        
        console.log("[+] Root detection bypass installed");