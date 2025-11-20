Java.perform(function () {
    console.log("NON-ROOT GADGET ACTIVE - waiting for reCAPTCHA...");

    // Simple memory scanner for recaptcha tokens
    setInterval(function() {
        Memory.scan(Process.getModuleByName("libreddit").base, 0x20000000, "03A", {
            onMatch: function(address, size) {
                try {
                    var str = Memory.readUtf8String(address, 2000);
                    if (str.length > 800 && str.includes("03A") && str.includes("http")) {
                        console.log("TOKEN FOUND:\n" + str.substring(0, 500) + "...\n");
                    }
                } catch(e) {}
            },
            onComplete: function() {}
        });
    }, 2000);
});