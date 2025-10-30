      console.log("[*] Installing crypto monitors...");
        
        // Hook Cipher
        var Cipher = Java.use("javax.crypto.Cipher");
        
        Cipher.getInstance.overload('java.lang.String').implementation = function(transformation) {
            send({
                type: "crypto",
                message: "[Cipher.getInstance] " + transformation
            });
            return this.getInstance(transformation);
        };
        
        Cipher.init.overload('int', 'java.security.Key').implementation = function(mode, key) {
            var modeStr = (mode === 1) ? "ENCRYPT" : "DECRYPT";
            var algorithm = key.getAlgorithm();
            
            send({
                type: "crypto",
                message: "[Cipher.init] Mode: " + modeStr + " Algorithm: " + algorithm
            });
            
            return this.init(mode, key);
        };
        
        // Hook MessageDigest
        var MessageDigest = Java.use("java.security.MessageDigest");
        
        MessageDigest.getInstance.overload('java.lang.String').implementation = function(algorithm) {
            send({
                type: "crypto",
                message: "[MessageDigest.getInstance] " + algorithm
            });
            return this.getInstance(algorithm);
        };
        
        console.log("[+] Crypto monitors installed");