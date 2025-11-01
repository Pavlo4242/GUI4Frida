     console.log("[*] Installing UI tracking hooks...");
        
        // Hook View.OnClickListener
        var View = Java.use("android.view.View");
        View.performClick.implementation = function() {
            var viewId = "unknown";
            try {
                var resources = this.getResources();
                var id = this.getId();
                if (id > 0) {
                    viewId = resources.getResourceEntryName(id);
                }
            } catch(e) {}
            
            var className = this.getClass().getName();
            var coords = [this.getX(), this.getY()];
            
            send({
                type: "ui",
                message: "[CLICK] View: " + className + " ID: " + viewId + " at " + JSON.stringify(coords)
            });
            
            return this.performClick();
        };
        
        // Hook Activity.startActivity
        var Activity = Java.use("android.app.Activity");
        Activity.startActivity.overload('android.content.Intent').implementation = function(intent) {
            var component = intent.getComponent();
            var action = intent.getAction();
            
            send({
                type: "ui",
                message: "[ACTIVITY_START] Component: " + component + " Action: " + action
            });
            
            return this.startActivity(intent);
        };
        
        // Hook Activity lifecycle
        Activity.onCreate.overload('android.os.Bundle').implementation = function(bundle) {
            send({
                type: "lifecycle",
                message: "[LIFECYCLE] onCreate: " + this.getClass().getName()
            });
            return this.onCreate(bundle);
        };
        
        Activity.onResume.implementation = function() {
            send({
                type: "lifecycle",
                message: "[LIFECYCLE] onResume: " + this.getClass().getName()
            });
            return this.onResume();
        };
        
        Activity.onPause.implementation = function() {
            send({
                type: "lifecycle",
                message: "[LIFECYCLE] onPause: " + this.getClass().getName()
            });
            return this.onPause();
        };
        
        console.log("[+] UI tracking hooks installed");