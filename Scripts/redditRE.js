
Java.perform(function () {
    const DEBUG = true;
    function log(m) { if (DEBUG) console.log("[reCAPTCHA-Steal] " + m); }

    // Reddit 2025 uses SafetyNet / Play Integrity + internal reCAPTCHA v3
    try {
        // 2025.45+ → com.reddit.mobile.recaptcha.RecaptchaClient
        const RecaptchaClient = Java.use("com.reddit.mobile.recaptcha.RecaptchaClient");
        RecaptchaClient.execute.overload('com.google.android.recaptcha.RecaptchaAction', 'java.util.Map').implementation = function(action, map) {
            const realResult = this.execute(action, map);
            const token = realResult.getTokenResultSync(); // <-- this is the GOOD token
            console.log("\n=== REAL reCAPTCHA TOKEN ===");
            console.log(token);
            console.log("Action:", action.toString());
            console.log("=== COPY THIS NOW ===\n");
            return realResult;
        };
        log("Real reCAPTCHA hook installed");
    } catch (e) { log("Hook failed (normal on older builds): " + e); }

    // Fallback for older Reddit builds (still used in some regions)
    try {
        const RecaptchaTasksClient = Java.use("com.google.android.gms.tasks.Tasks");
        // not needed if above works
    } catch (e) {}
});