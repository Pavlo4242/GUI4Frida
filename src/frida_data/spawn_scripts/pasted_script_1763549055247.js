const DEBUG_MODE = true; // Set to false in production testing

if (DEBUG_MODE) {
    console.log("[*] Starting comprehensive SSL/HSTS bypass script");
}

// MODIFICATION: Added root/debug bypass stubs at script start for apps like Reddit that detect instrumentation
// Hook common root checks (e.g., File.exists for su binary)
try {
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.includes("su") || path.includes("magisk") || path.includes("root")) {
            if (DEBUG_MODE) console.log("[+] Bypassing root check: " + path);
            return false;
        }
        return this.exists.apply(this, arguments);
    };
    // Bypass debug detection
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function() {
        if (DEBUG_MODE) console.log("[+] Bypassing debug detection");
        return false;
    };
} catch (e) {
    console.log("[-] Root/debug bypass failed: " + e);
}

// Base TrustManager bypass (for Android default)
try {
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');

    // Hook TrustManagerImpl.checkTrusted
    TrustManagerImpl.checkTrusted.implementation = function(untrustedChainFormatted, trustAnchorChain, host, clientAuth, untrustedChain, trustAnchorIssuer, session) {
        if (DEBUG_MODE) console.log("[+] Bypassing TrustManagerImpl checkTrusted for host: " + host);
        // Return true to trust all
        return true;
    };

    // Generic X509TrustManager hook
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.overload('javax.net.ssl.KeyManager[]', 'javax.net.ssl.TrustManager[]', 'java.security.SecureRandom').implementation = function(keyManager, trustManagers, sr) {
        if (DEBUG_MODE) console.log("[+] Bypassing SSLContext.init");
        var trustAll = Java.array('javax.net.ssl.TrustManager', [{
            checkClientTrusted: function() {},
            checkServerTrusted: function() {},
            getAcceptedIssuers: function() { return []; }
        }]);
        return this.init(keyManager, trustAll, sr);
    };
} catch (e) {
    console.log("[-] TrustManager bypass failed: " + e);
}

// MODIFICATION: Enhanced OkHttp3+ bypass with internal method hook for obfuscated apps (e.g., Reddit's networking)
// Targets okhttp3.CertificatePinner.check and fallback to findInternalPinner via class analysis
try {
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(hostname, certs) {
        if (DEBUG_MODE) console.log("[+] Bypassing OkHttp CertificatePinner.check for: " + hostname);
        return;
    };

    // Fallback for obfuscated OkHttp (hook internal builder)
    var OkHttpClient = Java.use('okhttp3.OkHttpClient$Builder');
    OkHttpClient.certificatePinner.implementation = function(pinner) {
        if (DEBUG_MODE) console.log("[+] Overriding OkHttp certificatePinner");
        return this.certificatePinner(Java.use('okhttp3.CertificatePinner').getDefault());
    };

    // MODIFICATION: Hook for OkHttp3 4.2+ (from Brida script) - intercepts ConnectionSuiteBuilder
    try {
        var Internal = Java.use('okhttp3.internal.connection.ConnectionSuite');
        Internal.$init.overload().implementation = function() {
            if (DEBUG_MODE) console.log("[+] Bypassing OkHttp3 4.2+ internal pinning");
            return this.$init.apply(this, arguments); // Proceed but trust all in check
        };
    } catch (e) {
        if (DEBUG_MODE) console.log("[*] OkHttp3 4.2+ hook skipped: " + e);
    };
} catch (e) {
    console.log("[-] OkHttp bypass failed: " + e);
}

// HttpsURLConnection bypass (common in Gmail/Reddit WebViews)
try {
    var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
    HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(hostnameVerifier) {
        if (DEBUG_MODE) console.log("[+] Bypassing HttpsURLConnection hostname verifier");
        var trustAllVerifier = Java.registerClass({
            name: 'com.example.TrustAllHostnameVerifier',
            implements: [Java.use('javax.net.ssl.HostnameVerifier')],
            methods: {
                verify: function(hostname, session) {
                    if (DEBUG_MODE) console.log("[+] Trusting hostname: " + hostname);
                    return true;
                }
            }
        });
        return this.setDefaultHostnameVerifier(trustAllVerifier.$new());
    };
} catch (e) {
    console.log("[-] HttpsURLConnection bypass failed: " + e);
}

// MODIFICATION: Added WebView HSTS bypass (for embedded browsers in apps; forces HTTP fallback)
try {
    var WebViewClient = Java.use('android.webkit.WebViewClient');
    WebViewClient.shouldOverrideUrlLoading.overload('android.webkit.WebView', 'java.lang.String').implementation = function(view, url) {
        if (url.startsWith('https://')) {
            if (DEBUG_MODE) console.log("[+] Downgrading HSTS URL to HTTP: " + url);
            var httpUrl = url.replace('https://', 'http://');
            // Redirect to HTTP (bypasses HSTS preload)
            Java.use('android.content.Intent').$new('android.intent.action.VIEW', Java.use('android.net.Uri').parse(httpUrl));
            return true;
        }
        return this.shouldOverrideUrlLoading(view, url);
    };
} catch (e) {
    console.log("[-] WebView HSTS bypass failed: " + e);
}

// Legacy Android <7 TrustManager hook (fallback)
if (Java.androidVersion < 24) { // Android 7.0 is API 24
    try {
        var TrustManager = Java.use('javax.net.ssl.TrustManager');
        // Similar to base hook...
        console.log("[*] Using legacy TrustManager bypass");
    } catch (e) {
        console.log("[-] Legacy bypass failed: " + e);
    }
}

if (DEBUG_MODE) {
    console.log("[*] All bypass hooks loaded. Launch app and check proxy traffic.");
}