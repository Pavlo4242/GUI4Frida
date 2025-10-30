      console.log("[*] Installing Activity lifecycle monitors...");
        
        var Activity = Java.use("android.app.Activity");
        
        Activity.onCreate.overload('android.os.Bundle').implementation = function(bundle) {
            var activityName = this.getClass().getName();
            var intent = this.getIntent();
            
            var extras = "none";
            if (intent != null) {
                try {
                    var bundleExtras = intent.getExtras();
                    if (bundleExtras != null) {
                        extras = bundleExtras.toString();
                    }
                } catch(e) {}
            }
            
            send({
                type: "lifecycle",
                message: "[onCreate] " + activityName + " extras: " + extras
            });
            
            return this.onCreate(bundle);
        };
        
        Activity.onStart.implementation = function() {
            send({
                type: "lifecycle",
                message: "[onStart] " + this.getClass().getName()
            });
            return this.onStart();
        };
        
        Activity.onResume.implementation = function() {
            send({
                type: "lifecycle",
                message: "[onResume] " + this.getClass().getName()
            });
            return this.onResume();
        };
        
        Activity.onPause.implementation = function() {
            send({
                type: "lifecycle",
                message: "[onPause] " + this.getClass().getName()
            });
            return this.onPause();
        };
        
        Activity.onStop.implementation = function() {
            send({
                type: "lifecycle",
                message: "[onStop] " + this.getClass().getName()
            });
            return this.onStop();
        };
        
        Activity.onDestroy.implementation = function() {
            send({
                type: "lifecycle",
                message: "[onDestroy] " + this.getClass().getName()
            });
            return this.onDestroy();
        };
        
        Activity.finish.implementation = function() {
            var stack = Java.use("android.util.Log").getStackTraceString(
                Java.use("java.lang.Exception").$new()
            );
            
            send({
                type: "lifecycle",
                message: "[finish] " + this.getClass().getName() + "\\nStack:\\n" + stack
            });
            
            return this.finish();
        };
        
        console.log("[+] Activity lifecycle monitors installed");