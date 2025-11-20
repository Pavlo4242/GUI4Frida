Java.perform(function () {
    const DEBUG = true;
    function log(m) { if (DEBUG) console.log("[reCAPTCHA-Steal] " + m); }

    // Reddit 2025 uses SafetyNet / Play Integrity + internal reCAPTCHA v3
    try {
        // 2025.45+ → com.reddit.mobile.recaptcha.RecaptchaClient
        const RecaptchaClient = Java.use("com.reddit.mobile.recaptcha.RecaptchaClient");
        
        RecaptchaClient.execute.overload('com.google.android.recaptcha.RecaptchaAction', 'java.util.Map').implementation = function(action, map) {
            log("RecaptchaClient.execute called");
            
            // Call original method
            const realResult = this.execute(action, map);
            
            // Attempt to extract token
            try {
                // Assuming getTokenResultSync() exists in this custom wrapper
                const token = realResult.getTokenResultSync(); 
                log("CAPTCHA Token captured: " + token);
            } catch (err) {
                log("Failed to extract token synchronously: " + err);
            }

            // IMPORTANT: You must return the original object so the app continues
            return realResult; 
        };
    } catch (e) {
        log("RecaptchaClient hook failed (Class not found?): " + e);
    }

    // Fallback for older Reddit builds (still used in some regions)
    try {
        // const RecaptchaTasksClient = Java.use("com.google.android.gms.tasks.Tasks");
        // not needed if above works
    } catch (e) {
        log("Fallback hook failed: " + e);
    }
});