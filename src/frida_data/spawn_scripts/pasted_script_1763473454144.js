Java.perform(function() {
    console.log("[*] Attaching to FavoritesFragment to find its ViewModel and methods...");

    const FavoritesFragment = Java.use('com.grindrapp.android.favorites.presentation.ui.FavoritesFragment');

    FavoritesFragment.onViewCreated.implementation = function(view, savedInstanceState) {
        console.log("[+] FavoritesFragment.onViewCreated() hooked.");
        this.onViewCreated(view, savedInstanceState);

        try {
            // ViewModels are often fields within the Fragment class
            const fields = this.getClass().getDeclaredFields();
            for (let i = 0; i < fields.length; i++) {
                const field = fields[i];
                if (field.getType().getName().includes('ViewModel')) {
                    field.setAccessible(true);
                    const viewModelInstance = field.get(this);
                    const viewModelClass = viewModelInstance.getClass();
                    
                    console.log(`\n[!!!] Found ViewModel: ${viewModelClass.getName()} [!!!]`);
                    console.log("[+] Listing its methods. Look for names like 'refresh', 'load', 'fetch', 'getFavorites':");

                    const methods = viewModelClass.getDeclaredMethods();
                    methods.forEach(function(method) {
                        console.log(`    - ${method.getName()}`);
                    });
                    console.log("\n");
                }
            }
        } catch(e) {
            console.log("[-] Error finding ViewModel: " + e);
        }
    };
});