java.perform(function() {
    console.log("[+] Hooking TrustManager to bypass Android 7+ Security & SSL Pinning...");

    var array_list = Java.use("java.util.ArrayList");
    var ApiClient = Java.use("com.android.org.conscrypt.TrustManagerImpl");

    // 1. Trust ALL Certificates (Bypasses "User Cert" restriction)
    ApiClient.checkTrustedRecursive.implementation = function(certs, host, clientAuth, untrustedChain, trustedChain, used) {
        // console.log("[+] Bypassing TrustManagerImpl check for: " + host);
        return array_list.$new();
    };

    // 2. Bypass OkHttp Certificate Pinning (Used by Reddit)
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            // console.log("[+] Bypassing OkHttp Pinning for: " + hostname);
            return;
        };
    } catch (err) {
        console.log("[-] OkHttp 3.x Pinner not found, trying 4.x or obfuscated...");
    }

    // 3. Generic SSLContext Bypass (The "Nuke it" approach)
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function(a, b, c) {
        // Create a custom TrustManager that trusts everything
        var TrustManager = Java.registerClass({
            name: 'com.sensepost.test.TrustManager',
            implements: [Java.use('javax.net.ssl.X509TrustManager')],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });
        var TrustManagers = [TrustManager.$new()];
        // Call original init with OUR TrustManager
        this.init(a, TrustManagers, c);
    };

    console.log("[+] SSL Bypass Active. Check Charles Proxy now.");
});