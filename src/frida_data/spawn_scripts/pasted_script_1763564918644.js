Java.perform(function () {
    console.log("\n[Reddit 2025.45+ Complete Bypass] Loaded – waiting for password screen\n");

    // 1. SSL Pinning Bypass
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function () {
            return arguments[0];
        };
        TrustManagerImpl.checkServerTrusted.overload("[Ljava.security.cert.X509Certificate;", "java.lang.String").implementation = function () {};
        console.log("[+] Conscrypt TrustManager bypassed");
    } catch (e) {}

    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function () {};
        console.log("[+] OkHttp CertificatePinner bypassed");
    } catch (e) {}

    // 2. Loud message when you reach password screen
    setTimeout(function () {
        console.log("\n\n=== YOU ARE ON THE PASSWORD SCREEN ===\n");
        console.log("Type password twice → tap Continue → real token prints below instantly\n\n");
    }, 4000);

    // 3. Hook the exact "Continue" button tap
    try {
        var ViewModel = Java.use("com.reddit.screen.register.password.RegisterPasswordViewModel");
        ViewModel.submit.implementation = function () {
            console.log("\n\nCONTINUE BUTTON TAPPED – STEALING reCAPTCHA TOKEN NOW!\n");
            return this.submit.apply(this, arguments);
        };
        console.log("[+] Hooked RegisterPasswordViewModel.submit");
    } catch (e) {}

    // 4. Real reCAPTCHA token stealer (works on every 2025 build)
    setImmediate(function () {
        Java.scheduleOnMainThread(function () {
            try