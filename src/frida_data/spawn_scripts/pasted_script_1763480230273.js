Java.perform(function() {
    console.log("[*] Grindr Master UI Fix v6 (WeakReference) loaded.");
    console.log("[*] This is the definitive crash-proof version.");

    // --- ‼️ CONFIGURATION ‼️ ---
    const CASCADE_COLUMNS = 4;
    const FAVORITES_COLUMNS = 4;
    const FAVORITES_REFRESH_METHOD = "H";
    // --------------------------

    const RecyclerView = Java.use('androidx.recyclerview.widget.RecyclerView');
    const RecyclerViewLayoutParams = Java.use('androidx.recyclerview.widget.RecyclerView$LayoutParams');
    const ViewGroup = Java.use('android.view.ViewGroup');
    const Runnable = Java.use('java.lang.Runnable');
    const WeakReference = Java.use('java.lang.ref.WeakReference');

    function findRecyclerViewRecursively(view) {
        if (!view) return null;
        if (RecyclerView.class.isInstance(view)) return Java.cast(view, RecyclerView);
        if (ViewGroup.class.isInstance(view)) {
            const viewGroup = Java.cast(view, ViewGroup);
            for (let i = 0; i < viewGroup.getChildCount(); i++) {
                const found = findRecyclerViewRecursively(viewGroup.getChildAt(i));
                if (found) return found;
            }
        }
        return null;
    }

    function applyGridFix(fragment, columnCount) {
        const view = fragment.getView();
        if (!fragment.isAdded() || view === null) return;
        
        const recyclerView = findRecyclerViewRecursively(view);
        if (recyclerView) {
            console.log(`[+] Found RecyclerView in ${fragment.getClass().getName()}. Applying ${columnCount}-column fix.`);
            const context = fragment.getContext();
            recyclerView.getLayoutManager().setSpanCount(columnCount);
            const adapter = recyclerView.getAdapter();

            if (!adapter.isGridHooked_v6) {
                const adapterClass = Java.use(adapter.getClass().getName());
                adapterClass.onBindViewHolder.implementation = function(viewHolder, position) {
                    this.onBindViewHolder(viewHolder, position);
                    const itemView = viewHolder.itemView.value;
                    if (itemView === null) return;
                    const itemSize = context.getResources().getDisplayMetrics().widthPixels.value / columnCount;
                    itemView.setLayoutParams(RecyclerViewLayoutParams.$new(itemSize, itemSize));
                };
                adapter.isGridHooked_v6 = true;
                console.log(`[+] Adapter ${adapter.getClass().getName()} hooked successfully.`);
            }
        } else {
            console.log(`[-] FAILED to find RecyclerView in ${fragment.getClass().getName()}.`);
        }
    }

    function createAndPostRunnable(fragment, columnCount, isFavorites) {
        const view = fragment.getView();
        if (view) {
            // Create a WeakReference to the fragment. This does NOT prevent it from being destroyed.
            const fragmentRef = WeakReference.$new(fragment);

            const GridFixRunnable = Java.registerClass({
                name: 'com.grindrplus.hooks.GridFixRunnable' + Math.random().toString(36).substring(7),
                implements: [Runnable],
                methods: {
                    run: function() {
                        // At the moment of execution, get the fragment from the WeakReference.
                        const fragment = fragmentRef.get();

                        // [!!!] THE CRASH FIX [!!!]
                        // If the fragment is null, it means it was destroyed. Do nothing.
                        if (fragment === null) {
                            console.log("[INFO] Runnable executed, but its fragment was destroyed. Exiting safely.");
                            return;
                        }

                        // If we are here, the fragment is still valid. It's now safe to proceed.
                        applyGridFix(fragment, columnCount);

                        if (isFavorites) {
                            try {
                                const fields = fragment.getClass().getDeclaredFields();
                                for (let i = 0; i < fields.length; i++) {
                                    const field = fields[i];
                                    if (field.getType().getName().includes('ViewModel')) {
                                        field.setAccessible(true);
                                        const viewModel = field.get(fragment);
                                        console.log(`[+] Runnable calling refresh method '${FAVORITES_REFRESH_METHOD}' on ViewModel.`);
                                        viewModel[FAVORITES_REFRESH_METHOD]();
                                        break;
                                    }
                                }
                            } catch(e) { console.error(`[-] Runnable failed to refresh favorites: ${e}`); }
                        }
                    }
                }
            });

            view.post(GridFixRunnable.$new());
            console.log(`[INFO] Posted grid fix runnable for ${fragment.getClass().getName()}.`);
        }
    }
    
    // --- HOOKS ---
    const CascadeFragment = Java.use('com.grindrapp.android.ui.browse.CascadeFragment');
    CascadeFragment.onHiddenChanged.implementation = function(hidden) {
        this.onHiddenChanged(hidden);
        if (!hidden) createAndPostRunnable(this, CASCADE_COLUMNS, false);
    };

    const FavoritesFragment = Java.use('com.grindrapp.android.favorites.presentation.ui.FavoritesFragment');
    FavoritesFragment.onHiddenChanged.implementation = function(hidden) {
        this.onHiddenChanged(hidden);
        if (!hidden) createAndPostRunnable(this, FAVORITES_COLUMNS, true);
    };
    
    console.log("[+] Hooks for CascadeFragment and FavoritesFragment are active.");
});