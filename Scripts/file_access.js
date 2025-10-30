      console.log("[*] Installing file access monitors...");
        
        var File = Java.use("java.io.File");
        var FileInputStream = Java.use("java.io.FileInputStream");
        var FileOutputStream = Java.use("java.io.FileOutputStream");
        
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            var result = this.exists();
            
            send({
                type: "general",
                message: "[File.exists] " + path + " = " + result
            });
            
            return result;
        };
        
        FileInputStream.$init.overload('java.io.File').implementation = function(file) {
            send({
                type: "general",
                message: "[FileRead] " + file.getAbsolutePath()
            });
            return this.$init(file);
        };
        
        FileOutputStream.$init.overload('java.io.File').implementation = function(file) {
            send({
                type: "general",
                message: "[FileWrite] " + file.getAbsolutePath()
            });
            return this.$init(file);
        };
        
        console.log("[+] File access monitors installed");