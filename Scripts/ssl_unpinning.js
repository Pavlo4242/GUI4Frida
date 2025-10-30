      console.log("[*] Installing SSL unpinning...");
        
        // OkHttp CertificatePinner
        try {
            var CertificatePinner = Java.use("okhttp3.CertificatePinner");
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
                send({
                    type: "network",
                    message: "[SSL] Bypassed certificate pinning for: " + hostname
                });
                return;
            };
        } catch(e) {}
        
        // TrustManager
        try {
            var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
            var SSLContext = Java.use("javax.net.ssl.SSLContext");
            
            var TrustManager = Java.registerClass({
                name: 'com.fake.TrustManager',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function(chain, authType) {},
                    checkServerTrusted: function(chain, authType) {},
                    getAcceptedIssuers: function() { return []; }
                }
            });
            
            var TrustManagers = [TrustManager.$new()];
            var SSLContext_init = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
            
            SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
                send({
                    type: "network",
                    message: "[SSL] Installing custom TrustManager"
                });
                SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
            };
        } catch(e) {
            console.log("[-] TrustManager hook failed: " + e);
        }
        
        console.log("[+] SSL unpinning installed");