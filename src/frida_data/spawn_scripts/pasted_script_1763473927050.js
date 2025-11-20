Java.perform(function() {
    console.log("[*] Grindr Master UI Fix script loaded.");
    console.log("[*] Targeting onHiddenChanged for robust tab switching.");

    // --- ‼️ CONFIGURATION ‼️ ---
    const CASCADE_COLUMNS = 4;          // Set desired columns for the main Browse grid (e.g., 4 or 5)
    const FAVORITES_COLUMNS = 4;        // Set desired columns for the Favorites grid
    const FAVORITES_REFRESH_METHOD = "H"; // Based on your trace, this is the likely refresh method.
    // --------------------------

    const RecyclerView = Java.use('androidx.recyclerview.widget.RecyclerView');
    const RecyclerViewLayoutParams = Java.use('androidx.recyclerview.widget.RecyclerView$LayoutParams');
    const ViewGroup = Java.use('android.view.ViewGroup');

    /**
     * A reusable function to find a RecyclerView within a given view,
     * modify its layout, and fix the item distortion issue.
     */
    function applyGridFix(fragment, view, columnCount) {
        if (!view) {
            console.log(`[-] View for ${fragment.getClass().getName()} is null. Skipping fix.`);
            return;
        }

        try {
            const context = fragment.getContext();
            const viewGroup = Java.cast(view, ViewGroup);
            
            // Dynamically find the RecyclerView instance
            for (let i = 0; i < viewGroup.getChildCount(); i++) {
                const child = viewGroup.getChildAt(i);
                if (RecyclerView.class.isInstance(child)) {
                    console.log(`[+] Found RecyclerView in ${fragment.getClass().getName()}. Applying ${columnCount}-column fix.`);
                    const recyclerView = Java.cast(child, RecyclerView);

                    // 1. Set the column count
                    const gridLayoutManager = recyclerView.getLayoutManager();
                    gridLayoutManager.setSpanCount(columnCount);

                    // 2. Hook the adapter to resize items and prevent distortion
                    const adapter = recyclerView.getAdapter();
                    const adapterClass = Java.use(adapter.getClass().getName());

                    // Use a flag to prevent hooking the same adapter multiple times
                    if (!adapter.isGridHooked) {
                        adapterClass.onBindViewHolder.implementation = function(viewHolder, position) {
                            // Always call the original method first!
                            this.onBindViewHolder(viewHolder, position);
                            
                            const itemView = viewHolder.itemView.value;
                            const displayMetrics = context.getResources().getDisplayMetrics();
                            const itemSize = displayMetrics.widthPixels.value / columnCount;

                            // This is the critical distortion fix
                            const newLayoutParams = RecyclerViewLayoutParams.$new(itemSize, itemSize);
                            itemView.setLayoutParams(newLayoutParams);
                        };
                        adapter.isGridHooked = true; // Set our custom flag
                        console.log(`[+] Adapter ${adapterClass.getName()} hooked for item resizing.`);
                    }
                    return; // We found and fixed the RecyclerView, no need to continue looping.
                }
            }
            console.log(`[-] Could not find a RecyclerView inside ${fragment.getClass().getName()}.`);
        } catch (e) {
            console.error(`[-] Error applying grid fix to ${fragment.getClass().getName()}: ${e}`);
        }
    }

    // --- HOOK FOR THE MAIN BROWSE (CASCADE) TAB ---
    try {
        const CascadeFragment = Java.use('com.grindrapp.android.ui.browse.CascadeFragment');
        CascadeFragment.onHiddenChanged.implementation = function(hidden) {
            console.log(`[CASCADE] onHiddenChanged, hidden: ${hidden}`);
            if (!hidden) {
                // Fragment is now VISIBLE, apply our grid layout fix.
                // We use a small delay to ensure the view is fully laid out.
                setTimeout(() => {
                    applyGridFix(this, this.getView(), CASCADE_COLUMNS);
                }, 100);
            }
            this.onHiddenChanged(hidden); // Call original method
        };
        console.log("[+] Successfully hooked CascadeFragment.onHiddenChanged.");
    } catch(e) {
        console.error("[-] Failed to hook CascadeFragment: " + e);
    }
    
    // --- HOOK FOR THE FAVORITES TAB ---
    try {
        const FavoritesFragment = Java.use('com.grindrapp.android.favorites.presentation.ui.FavoritesFragment');
        FavoritesFragment.onHiddenChanged.implementation = function(hidden) {
            console.log(`[FAVORITES] onHiddenChanged, hidden: ${hidden}`);
            if (!hidden) {
                // Fragment is now VISIBLE.
                setTimeout(() => {
                    // 1. Apply the same layout fix to the Favorites grid.
                    applyGridFix(this, this.getView(), FAVORITES_COLUMNS);

                    // 2. Force the online status refresh by calling the identified method.
                    try {
                        const fields = this.getClass().getDeclaredFields();
                        for (let i = 0; i < fields.length; i++) {
                            const field = fields[i];
                            if (field.getType().getName().includes('ViewModel')) {
                                field.setAccessible(true);
                                const viewModelInstance = field.get(this);
                                console.log(`[+] Found ViewModel: ${viewModelInstance.getClass().getName()}. Calling refresh method '${FAVORITES_REFRESH_METHOD}'...`);
                                viewModelInstance[FAVORITES_REFRESH_METHOD]();
                                return;
                            }
                        }
                    } catch(e) {
                        console.error("[-] Failed to call favorites refresh method: " + e);
                    }
                }, 100);
            }
            this.onHiddenChanged(hidden); // Call original method
        };
        console.log("[+] Successfully hooked FavoritesFragment.onHiddenChanged.");
    } catch(e) {
        console.error("[-] Failed to hook FavoritesFragment: " + e);
    }
});