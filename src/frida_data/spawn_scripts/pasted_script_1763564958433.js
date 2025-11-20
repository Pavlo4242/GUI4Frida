Java.perform(function () {
    console.log("\nReddit 2025.45+ Complete Bypass LOADED\n");
    // SSL Pinning Bypass
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function () { return arguments[0]; };
        TrustManagerImpl.checkServerTrusted.overload("[Ljava.security.cert.X509Certificate;", "java.lang.String").implementation = function () {};
        console.log("[+] TrustManager bypassed");
    } catch (e) { console.log("TrustManager not found yet"); }
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function () {};
        console.log("[+] OkHttp pinning bypassed");
    } catch (e) { }
    // Loud message when you reach password screen
    setTimeout(function () {
        console.log("\n=== YOU ARE NOW ON THE PASSWORD SCREEN ===\n");
        console.log("Type any password → tap Continue → token prints in 

    // Hook Continue button
    try {
        var ViewModel = Java.use("com.reddit.screen.register.password.RegisterPasswordViewModel");
        ViewModel.submit.implementation = function () {
            console.log("\nCONTINUE TAPPED – GRABBING REAL TOKEN NOW!\n");
            return this.submit.apply(this, arguments);
        };
        console.log("[+] Hooked submit()");
    } catch (e) { }
    // reCAPTCHA token stealer – works 100% on 2025.45+
    setTimeout(function () {
        try {
            var RecaptchaClient = Java.use("com.reddit.mobile.recaptcha.RecaptchaClient");
            RecaptchaClient.execute.overload("com.google.android.recaptcha.RecaptchaAction", "java.util.Map").implementation = function (action, map) {
                var result = this.execute(action, map);
                try {
                    var token = result.getTokenResultSync !== null ? result.getTokenResultSync() : result.getTokenResult();
                    console.log("\nREAL RECAPTCHA TOKEN (COPY THIS NOW):\n");
                    console.log(token);
                    console.log("\nAction: " + action.toString() + "\n");
                } catch (err) {
                    console.log("Token not ready yet (normal)");
                }
                return result;
            };
            console.log("[+] reCAPTCHA stealer ACTIVE");
        } catch (e) {
            console.log("RecaptchaClient not loaded yet – waiting...");
        }
    }, 2000);
    console.log("All hooks installed – ready!\n");
});