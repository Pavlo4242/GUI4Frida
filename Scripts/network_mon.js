      console.log("[*] Installing network monitors...");
        
        // Hook OkHttp
        try {
            var OkHttpClient = Java.use("okhttp3.OkHttpClient");
            var Request = Java.use("okhttp3.Request");
            
            OkHttpClient.newCall.implementation = function(request) {
                var url = request.url().toString();
                var method = request.method();
                
                send({
                    type: "network",
                    message: "[HTTP] " + method + " " + url
                });
                
                // Log headers
                var headers = request.headers();
                for (var i = 0; i < headers.size(); i++) {
                    send({
                        type: "network",
                        message: "  Header: " + headers.name(i) + ": " + headers.value(i)
                    });
                }
                
                return this.newCall(request);
            };
            
            console.log("[+] OkHttp hooks installed");
        } catch(e) {
            console.log("[-] OkHttp not found: " + e);
        }
        
        // Hook HttpURLConnection
        try {
            var HttpURLConnection = Java.use("java.net.HttpURLConnection");
            
            HttpURLConnection.getInputStream.implementation = function() {
                var url = this.getURL().toString();
                var method = this.getRequestMethod();
                var responseCode = this.getResponseCode();
                
                send({
                    type: "network",
                    message: "[URLConnection] " + method + " " + url + " -> " + responseCode
                });
                
                return this.getInputStream();
            };
            
            console.log("[+] HttpURLConnection hooks installed");
        } catch(e) {
            console.log("[-] HttpURLConnection hook failed: " + e);
        }
        
        console.log("[+] Network monitors installed");