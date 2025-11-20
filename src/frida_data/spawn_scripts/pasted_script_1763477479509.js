Java.perform(function() {
    console.log("[*] Grindr Master UI Fix v5 (View.post Runnable) loaded.");
    console.log("[*] This version posts a runnable to the view queue to ensure the UI is fully ready.");

    // --- ‼️ CONFIGURATION ‼️ ---
    const CASCADE_COLUMNS = 4;
    const FAVORITES_COLUMNS = 3;
    const FAVORITES_REFRESH_METHOD = "H";
    // --------------------------

    const RecyclerView = Java.use('androidx.recyclerview.widget.RecyclerView');
    const RecyclerViewLayoutParams = Java.use('androidx.recyclerview.widget.RecyclerView$LayoutParams');
    const ViewGroup = Java.use('android.view.ViewGroup');
    const Runnable = Java.use('java.lang.Runnable');

    function findRecyclerViewRecursively(view, depth = 0) {
        if (!view) return null;
        const indent = "  ".repeat(depth);
        // Breadcrumb log to see the traversal path
        // console.log(`${indent}Inspecting view: ${view.getClass().getName()}`);

        if (RecyclerView.class.isInstance(view)) {
            console.log(`${indent}>>> SUCCESS: Found RecyclerView!`);
            return Java.cast(view, RecyclerView);
        }

        if (ViewGroup.class.isInstance(view)) {
            const viewGroup = Java.cast(view, ViewGroup);
            for (let i = 0; i < viewGroup.getChildCount(); i++) {
                const child = viewGroup.getChildAt(i);
                const found = findRecyclerViewRecursively(child, depth + 1);
                if (found) {
                    return found;
                }
            }
        }
        return null;
    }

    function applyGridFix(fragment, columnCount) {
        const view = fragment.getView();
        if (!fragment.isAdded() || view === null) return;

        console.log(`[+] Now running grid fix for ${fragment.getClass().getName()}. Starting deep search...`);
        const recyclerView = findRecyclerViewRecursively(view);

        if (recyclerView) {
            try {
                const context = fragment.getContext();
                recyclerView.getLayoutManager().setSpanCount(columnCount);
                const adapter = recyclerView.getAdapter();

                if (!adapter.isGridHooked_v5) {
                    const adapterClass = Java.use(adapter.getClass().getName());
                    adapterClass.onBindViewHolder.implementation = function(viewHolder, position) {
                        this.onBindViewHolder(viewHolder, position);
                        const itemView = viewHolder.itemView.value;
                        if (itemView === null) return;
                        const itemSize = context.getResources().getDisplayMetrics().widthPixels.value / columnCount;
                        itemView.setLayoutParams(RecyclerViewLayoutParams.$new(itemSize, itemSize));
                    };
                    adapter.isGridHooked_v5 = true;
                    console.log(`[+] Adapter ${adapter.getClass().getName()} hooked successfully.`);
                }
            } catch (e) {
                console.error(`[-] Error during grid modification: ${e}`);
            }
        } else {
            console.log(`[-] FAILED to find a RecyclerView in ${fragment.getClass().getName()}.`);
        }
    }

    function createAndPostRunnable(fragment, columnCount, isFavorites) {
        const view = fragment.getView();
        if (view) {
            // We create a new Java Runnable object on the fly for Frida to use.
            const GridFixRunnable = Java.registerClass({
                name: 'com.grindrplus.hooks.GridFixRunnable' + Math.random().toString(36).substring(2, 15),
                implements: [Runnable],
                methods: {
                    run: function() {
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
            console.log(`[INFO] Posted grid fix runnable to the view queue for ${fragment.getClass().getName()}.`);
        }
    }

    // --- HOOKS ---
    try {
        const CascadeFragment = Java.use('com.grindrapp.android.ui.browse.CascadeFragment');
        CascadeFragment.onHiddenChanged.implementation = function(hidden) {
            this.onHiddenChanged(hidden);
            if (!hidden) {
                createAndPostRunnable(this, CASCADE_COLUMNS, false);
            }
        };
        console.log("[+] Hooked CascadeFragment.");
    } catch(e) { console.error("[-] Failed to hook CascadeFragment: " + e); }
    
    try {
        const FavoritesFragment = Java.use('com.grindrapp.android.favorites.presentation.ui.FavoritesFragment');
        FavoritesFragment.onHiddenChanged.implementation = function(hidden) {
            this.onHiddenChanged(hidden);
            if (!hidden) {
                createAndPostRunnable(this, FAVORITES_COLUMNS, true);
            }
        };
        console.log("[+] Hooked FavoritesFragment.");
    } catch(e) { console.error("[-] Failed to hook FavoritesFragment: " + e); }
});