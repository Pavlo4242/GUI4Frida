/**
 * Safe Frida script to trace Grindr cascade profile display
 * 
 * Usage:
 * frida -U -f com.grindrapp.android -l grindr_cascade.js --no-pause
 */

console.log("[*] Grindr Cascade Tracer Loading...");

Java.perform(function() {
    console.log("[*] Java runtime loaded");

    // Just inspect the class structure without hooking
    try {
        const CachedProfile = Java.use("com.grindrapp.android.persistence.model.serverdrivencascade.ServerDrivenCascadeCachedProfile");
        console.log("[+] Found ServerDrivenCascadeCachedProfile");
        
        // List all fields
        const fields = CachedProfile.class.getDeclaredFields();
        console.log("\n[*] ===== ServerDrivenCascadeCachedProfile FIELDS =====");
        fields.forEach(function(field) {
            console.log("    " + field.getName() + " : " + field.getType().getName());
        });
        console.log("[*] ===== END FIELDS =====\n");

    } catch (e) {
        console.log("[-] Error inspecting ServerDrivenCascadeCachedProfile: " + e);
    }

    // Inspect API response model
    try {
        const FullProfileV1 = Java.use("com.grindrapp.android.persistence.model.serverdrivencascade.CascadeItemData$FullProfileV1");
        console.log("[+] Found CascadeItemData$FullProfileV1");
        
        const fields = FullProfileV1.class.getDeclaredFields();
        console.log("\n[*] ===== CascadeItemData$FullProfileV1 FIELDS (API Response) =====");
        fields.forEach(function(field) {
            console.log("    " + field.getName() + " : " + field.getType().getName());
        });
        console.log("[*] ===== END FIELDS =====\n");
        
    } catch (e) {
        console.log("[-] Error inspecting FullProfileV1: " + e);
    }

    console.log("[*] Inspection complete. No hooks installed - app should run normally.");
    console.log("[*] Check the field lists above to see what's available.");
});