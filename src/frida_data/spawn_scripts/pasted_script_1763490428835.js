/ Filename: grindr_master_ui_fix_final.js

Java.perform(function() {
    console.log("[*] Grindr Master UI Fix (v5.1 - Final) loaded.");
    console.log("[*] Using view.post() based on detailed trace analysis.");

    // --- CONFIGURATION ---
    const CASCADE_COLUMNS = 4;
    const FAVORITES_COLUMNS = 4;
    const FAVORITES_REFRESH_METHOD = "H"; // Confirmed from your traces as a likely candidate
    // ---------------------

    const RecyclerView = Java.use('androidx.recyclerview.widget.RecyclerView');
    const RecyclerViewLayoutParams = Java.use('androidx.recyclerview.widget.RecyclerView$LayoutParams');
    const ViewGroup = Java.use('android.view.ViewGroup');
    const Runnable = Java.use('java.lang.Runnable');

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

            if (!adapter.isGridHooked_final) {
                const adapterClass = Java.use(adapter.getClass().getName());
                adapterClass.onBindViewHolder.implementation = function(viewHolder, position) {
                    this.onBindViewHolder(viewHolder, position);
                    const itemView = viewHolder.itemView.value;
                    if (itemView === null) return;
                    const itemSize = context.getResources().getDisplayMetrics().widthPixels.value / columnCount;
                    itemView.setLayoutParams(RecyclerViewLayoutParams.$new(itemSize, itemSize));
                };
                adapter.isGridHooked_final = true;
                console.log(`[+] Adapter ${adapter.getClass().getName()} hooked successfully.`);
            }
        } else {
            console.log(`[-] FAILED to find RecyclerView in ${fragment.getClass().getName()}.`);
        }
    }

    function createAndPostRunnable(fragment, columnCount, isFavorites) {
        const view = fragment.getView();
        if (view) {
            const GridFixRunnable = Java.registerClass({
                name: 'com.grindrplus.hooks.GridFixRunnable' + Math.random().toString(36).substring(7),
                implements: [Runnable],
                methods: {
                    run: function() {
                        applyGridFix(fragment, columnCount);
                        if (isFavorites) {
                            // Refresh logic
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