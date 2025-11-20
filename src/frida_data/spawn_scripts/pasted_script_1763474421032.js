Java.perform(function() {
    console.log("[*] Grindr Master UI Fix v2 (Crash-Proof) loaded.");
    console.log("[*] This version uses synchronous hooks with state validation.");

    // --- ‼️ CONFIGURATION ‼️ ---
    const CASCADE_COLUMNS = 4;
    const FAVORITES_COLUMNS = 4;
    const FAVORITES_REFRESH_METHOD = "H"; // From your previous trace
    // --------------------------

    const RecyclerView = Java.use('androidx.recyclerview.widget.RecyclerView');
    const RecyclerViewLayoutParams = Java.use('androidx.recyclerview.widget.RecyclerView$LayoutParams');
    const ViewGroup = Java.use('android.view.ViewGroup');

    /**
     * A reusable function to find a RecyclerView, modify its layout, and fix item distortion.
     * This now runs synchronously and includes safety checks.
     */
    function applyGridFix(fragment, columnCount) {
        // --- SAFETY CHECK ---
        // Do not proceed if the fragment isn't in a valid state or its view is gone.
        // This is the primary fix for the native crash.
        const view = fragment.getView();
        if (!fragment.isAdded() || view === null) {
            console.log(`[-] Fragment ${fragment.getClass().getName()} is not in a valid state. Skipping modifications.`);
            return;
        }

        try {
            const context = fragment.getContext();
            const viewGroup = Java.cast(view, ViewGroup);
            
            for (let i = 0; i < viewGroup.getChildCount(); i++) {
                const child = viewGroup.getChildAt(i);
                if (RecyclerView.class.isInstance(child)) {
                    console.log(`[+] Applying ${columnCount}-column fix to ${fragment.getClass().getName()}.`);
                    const recyclerView = Java.cast(child, RecyclerView);

                    const gridLayoutManager = recyclerView.getLayoutManager();
                    gridLayoutManager.setSpanCount(columnCount);

                    const adapter = recyclerView.getAdapter();
                    const adapterClass = Java.use(adapter.getClass().getName());

                    if (!adapter.isGridHooked_v2) { // Use a new flag
                        adapterClass.onBindViewHolder.implementation = function(viewHolder, position) {
                            this.onBindViewHolder(viewHolder, position);
                            
                            // A quick safety check inside the adapter hook as well
                            const itemView = viewHolder.itemView.value;
                            if (itemView === null) return;

                            const displayMetrics = context.getResources().getDisplayMetrics();
                            const itemSize = displayMetrics.widthPixels.value / columnCount;

                            const newLayoutParams = RecyclerViewLayoutParams.$new(itemSize, itemSize);
                            itemView.setLayoutParams(newLayoutParams);
                        };
                        adapter.isGridHooked_v2 = true;
                        console.log(`[+] Adapter ${adapterClass.getName()} hooked for item resizing.`);
                    }
                    return;
                }
            }
        } catch (e) {
            console.error(`[-] Error in applyGridFix for ${fragment.getClass().getName()}: ${e}`);
        }
    }

    // --- HOOK FOR THE MAIN BROWSE (CASCADE) TAB ---
    try {
        const CascadeFragment = Java.use('com.grindrapp.android.ui.browse.CascadeFragment');
        CascadeFragment.onHiddenChanged.implementation = function(hidden) {
            if (!hidden) { // Fragment is now VISIBLE
                applyGridFix(this, CASCADE_COLUMNS);
            }
            // Call the original method AFTER our modifications
            this.onHiddenChanged(hidden);
        };
        console.log("[+] Hooked CascadeFragment.onHiddenChanged successfully.");
    } catch(e) {
        console.error("[-] Failed to hook CascadeFragment: " + e);
    }
    
    // --- HOOK FOR THE FAVORITES TAB ---
    try {
        const FavoritesFragment = Java.use('com.grindrapp.android.favorites.presentation.ui.FavoritesFragment');
        FavoritesFragment.onHiddenChanged.implementation = function(hidden) {
            if (!hidden) { // Fragment is now VISIBLE
                // 1. Apply layout fix
                applyGridFix(this, FAVORITES_COLUMNS);

                // 2. Force online status refresh
                try {
                    const fields = this.getClass().getDeclaredFields();
                    for (let i = 0; i < fields.length; i++) {
                        const field = fields[i];
                        if (field.getType().getName().includes('ViewModel')) {
                            field.setAccessible(true);
                            const viewModelInstance = field.get(this);
                            console.log(`[+] Calling refresh method '${FAVORITES_REFRESH_METHOD}' on ViewModel.`);
                            viewModelInstance[FAVORITES_REFRESH_METHOD]();
                            break; // Exit loop after finding the ViewModel
                        }
                    }
                } catch(e) {
                    console.error("[-] Failed to call favorites refresh method: " + e);
                }
            }
             // Call the original method AFTER our modifications
            this.onHiddenChanged(hidden);
        };
        console.log("[+] Hooked FavoritesFragment.onHiddenChanged successfully.");
    } catch(e) {
        console.error("[-] Failed to hook FavoritesFragment: " + e);
    }
});