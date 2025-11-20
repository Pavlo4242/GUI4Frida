Java.perform(function () {
    console.log("[+] Reddit 2025.45+ bypass loaded");
    // SSL bypass
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function () { return arguments[0]; };
        TrustManagerImpl.checkServerTrusted.implementation = function () {};
        console.log("[+] TrustManager bypassed");
    } catch (e) {}
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.implementation = function () {};
        console.log("[+] OkHttp pinning bypassed");
    } catch (e) {}
    // Password screen message
    setTimeout(function () {
        console.log("\n=== PASSWORD SCREEN REACHED ===\nType password → tap Continue → token below\n");
    }, 4000);
    // Hook Continue button
    try {
        var VM = Java.use("com.reddit.screen.register.password.RegisterPasswordViewModel");
        VM.submit.implementation = function () {
            console.log("\nCONTINUE TAPPED → STEALING TOKEN NOW\n");
            return this.submit.apply(this, arguments);
        };
    } catch (e) {}
    // Real reCAPTCHA stealer
    setTimeout(function () {
        try {
            var RC = Java.use("com.reddit.mobile.recaptcha.RecaptchaClient");
            RC.execute.overload("com.google.android.recaptcha.RecaptchaAction", "java.util.Map").implementation = function (action, map) {
                var res = this.execute(action, map);
                try {
                    var token = res.getTokenResultSync ? res.getTokenResultSync() : res.getTokenResult();
                    console.log("\nREAL TOKEN (COPY NOW):\n" + token + "\n");
                } catch (e) {}
                return res;
            };
            console.log("[+] reCAPTCHA hook active");
        } catch (e) {}
    }, 1000);
    console.log("[+] All hooks ready – go create the account");
});