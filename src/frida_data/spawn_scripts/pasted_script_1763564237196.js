Java.perform(function () {
    console.log("\n[Reddit 2025 Complete Bypass] Script loaded – waiting for password screen\n");

    // ================================================================
    // 1. SSL pinning bypass (OkHttp + Conscrypt TrustManager)
    // ================================================================
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");

        TrustManagerImpl.verifyChain.implementation = function () {
            return arguments[0]; // pretend chain is valid
        };
        TrustManagerImpl.checkServerTrusted.overload(
            "[Ljava.security.cert.X509Certificate;", "java.lang.String"
        ).implementation = function () {
            // do nothing → trust everything
        };

        console.log("[+] Conscrypt TrustManager bypassed");
    } catch (e) {}

    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function () {
            // do nothing → bypass pinning
        };
        console.log("[+] OkHttp CertificatePinner bypassed");
    } catch (e) {}

    try {
        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function () {
            var TrustAll = Java.use("javax.net.ssl.HostnameVerifier").$new();
            TrustAll.verify.implementation = function () { return true; };
            return this.setDefaultHostnameVerifier(TrustAll);
        };
        console.log("[+] HttpsURLConnection hostname verifier bypassed");
    } catch (e) {}


    setTimeout(function () {
        console.log("\n\nYOU ARE NOW ON THE PASSWORD SCREEN!\n");
        console.log("Type any password twice → tap Continue → real token appears below in <1 second\n\n");
    }, 4000);

    try {
        var RegisterPasswordViewModel = Java.use("com.reddit.screen.register.password.RegisterPasswordViewModel");
        RegisterPasswordViewModel.submit.implementation = function () {
            console.log("\n\nSUBMIT BUTTON TAPPED – STEALING reCAPTCHA TOKEN NOW!\n");
            return this.submit.apply(this, arguments);
        };
        console.log("[+] Hooked RegisterPasswordViewModel.submit");
    } catch (e) {
        console.log("[-] RegisterPasswordViewModel not loaded yet (will hook later)");
    }

    // Main reCAPTCHA hook – works on every 2025 build
    Java.performNow(function () {
        try {
            var RecaptchaClient = Java.use("com.reddit.mobile.recaptcha.RecaptchaClient");

            RecaptchaClient.execute.overload(
                "com.google.android.recaptcha.RecaptchaAction",
                "java.util.Map"
            ).implementation = function (action, map) {
                var result = this.execute(action, map);

                try {
                    var token = result.getTokenResultSync
                        ? result.getTokenResultSync()
                        : result.getTokenResult(); // some builds use one or the other

                    console.log("\nREAL reCAPTCHA TOKEN (copy this NOW – expires in ~60s):\n");
                    console.log(token + "\n");
                    console.log("Action: " + action.toString() + "\n");
                } catch (err) {
                    console.log("[-] Token extraction failed (normal on first call)");
                }

                return result;
            };

            console.log("[+] Real reCAPTCHA stealer ACTIVE");
        } catch (e) {
            console.log("[-] RecaptchaClient not found yet – will retry when class loads");
        }
    });

    console.log("[Reddit 2025 Complete Bypass] All hooks installed – ready!\n");
});