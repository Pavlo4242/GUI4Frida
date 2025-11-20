Java.perform(function () {
    console.log("\n[*] Hooks loaded. Please open the Grindr app and navigate to Browse and Favorites tabs...\n");

    const Fragment = Java.use("androidx.fragment.app.Fragment");
    const View = Java.use("android.view.View");
    const ViewGroup = Java.use("android.view.ViewGroup");
    const RecyclerView = Java.use("androidx.recyclerview.widget.RecyclerView");

    // Hook onResume to detect which Fragment is actually on screen
    Fragment.onResume.implementation = function () {
        this.onResume();
        var fragmentClass = this.getClass();
        var fragmentName = fragmentClass.getName();
        
        // Only look at Grindr fragments
        if (fragmentName.includes("com.grindrapp") && !fragmentName.includes("Glide")) {
            console.log("==================================================");
            console.log("[+] CURRENT FRAGMENT: " + fragmentName);
            console.log("==================================================");

            // 1. INSPECT FIELDS (For UnlimitedProfiles Fix)
            // We look for fields that might hold the ViewModel
            console.log("--- [ FIELDS DUMP ] ---");
            var fields = fragmentClass.getDeclaredFields();
            fields.forEach(function(field) {
                field.setAccessible(true);
                try {
                    var value = field.get(this);
                    var type = field.getType().getName();
                    // Only print interesting fields (ViewModels, Lists, etc.)
                    if (value != null) {
                        console.log("Field Name: '" + field.getName() + "' | Type: " + type);
                    }
                } catch(e) {}
            }.bind(this));

            // 2. FIND RECYCLERVIEW (For Grid Layout Fix)
            var view = this.getView();
            if (view != null) {
                console.log("\n--- [ VIEW HIERARCHY SEARCH ] ---");
                findRecyclerView(view, "");
            }
            console.log("\n");
        }
    };

    function findRecyclerView(view, indent) {
        if (view == null) return;

        // Check if this is a RecyclerView
        if (RecyclerView.class.isInstance(view)) {
            var rv = Java.cast(view, RecyclerView);
            var id = view.getId();
            var idName = "UNKNOWN_ID";
            try {
                // Try to get the human-readable ID string (e.g., R.id.fragment_feed_recycler_view)
                idName = view.getContext().getResources().getResourceEntryName(id);
            } catch (e) {}

            console.log(indent + ">>> FOUND RECYCLERVIEW! <<<");
            console.log(indent + "    ID Int: " + id);
            console.log(indent + "    ID String: '" + idName + "'  <-- USE THIS IN KOTLIN");
            
            var lm = rv.getLayoutManager();
            console.log(indent + "    LayoutManager: " + (lm ? lm.getClass().getName() : "null"));
        }

        // Recursive search
        if (ViewGroup.class.isInstance(view)) {
            var vg = Java.cast(view, ViewGroup);
            var count = vg.getChildCount();
            for (var i = 0; i < count; i++) {
                findRecyclerView(vg.getChildAt(i), indent + "  ");
            }
        }
    }
});