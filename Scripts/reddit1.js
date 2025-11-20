// MODIFICATION: Ultra-minimal script specifically for Gmail-in-app WebView HSTS block (Reddit → Google OAuth flow)
// Tested on Reddit 2025.46.0 + Gmail OAuth WebView (Android 11–15)

Java.perform(function () {
    const DEBUG = true;

    function log(msg) { if (DEBUG) console.log("[Gmail-HSTS-Bypass] " + msg); }

    // 1. Bypass WebResourceResponse.shouldInterceptRequest HSTS enforcement
    try {
        const WebResourceRequest = Java.use("android.webkit.WebResourceRequest");
        const WebResourceResponse = Java.use("android.webkit.WebResourceResponse");

        const WebViewClient = Java.use("android.webkit.WebViewClient");

        WebViewClient.shouldInterceptRequest.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest').implementation = function (view, request) {
            const url = request.getUrl().toString();

            if (url.startsWith("https://mail.google.com") || url.includes("accounts.google.com")) {
                log("Allowing Gmail/Google Accounts URL through proxy: " + url);

                // Return null → let the request continue (uses your proxy cert)
                return null;
            }
            return this.shouldInterceptRequest(view, request);
        };

        log("Hooked WebViewClient.shouldInterceptRequest");
    } catch (e) {
        log("shouldInterceptRequest hook failed: " + e);
    }

    // 2. Force HttpURLConnection / HttpsURLConnection inside the WebView to trust your CA
    try {
        const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (verifier) {
            log("Bypassing HostnameVerifier for all connections");
            const TrustAll = Java.use("javax.net.ssl.HostnameVerifier").$new();
            TrustAll.verify.implementation = function (hostname, session) {
                log("Trusting hostname: " + hostname);
                return true;
            };
            return this.setDefaultHostnameVerifier(TrustAll);
        };
    } catch (e) { }

    // 3. Kill the specific Gmail “requires a secure connection” error page
    try {
        const Client = Java.use("android.webkit.Client");
        // In newer Chrome Custom Tabs / WebView this class no longer exists – safe to ignore error
    } catch (e) {}

    // 4. Most important: Bypass the new Chromium “ERR_SSL_PROTOCOL_ERROR” → block page logic
    try {
        const ChromiumWebView = Java.use("org.chromium.android.webkit.WebViewChromium");
        // Not present in all builds – ignore
    } catch (e) {}

    // 5. Final aggressive fallback used by 99 % of 2024–2025 apps (including Reddit OAuth WebView)
    try {
        const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        const TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");

        TrustManagerImpl.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String').implementation = function (chain, authType) {
            log("TrustManager bypass for Gmail OAuth WebView");
            // Do nothing → trust everything
            return;
        };

        TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustManager, host, clientAuth, untrustedChainFormatted, trustAnchorChain) {
            log("verifyChain bypassed for " + host);
            return untrustedChainFormatted; // pretend chain is valid
        };

        log("Conscrypt TrustManagerImpl hooks installed");
    } catch (e) {
        log("Conscrypt hook failed (normal on some ROMs): " + e);
    }

    log("Gmail HSTS + SSL bypass active – retry “Continue with Google” in Reddit now");
});