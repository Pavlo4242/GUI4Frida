 ----------------------------------------------------------
   full-spoof.js -  Frida + Xposed?->?Grindr
   ----------------------------------------------------------
   * Spoof Firebase signing & remote-config hash
   * Spoof image-library package name
   * Force Facebook login to web-fallback
   * Spoof ContextWrapper.getPackageName when FirebaseInstallationServiceClient calls it
   * Replace "grindr" in Firebase Messaging Metadata.getPackageInfo
   * (plus your previous anti-detection hooks - put the code further below)
 ---------------------------------------------------------- */

Java.perform(function () {
    /* 0??  CONFIG -------------------------------------------------------------- */
    const GRINDR_PACKAGE_NAME = "com.grindrapp.android";          // <-- change if your app's package differs
    const PACKAGE_SIGNATURE = "823f5a17c33b16b4775480b31607e7df35d67af8"; // the signature you want Firebase to see

    /* 1??  Firebase & Remote-Config - getFingerprintHashForPackage() ------------------------ */
    const firebaseClients = [
        "com.google.firebase.installations.remote.FirebaseInstallationServiceClient",
        "com.google.firebase.remoteconfig.internal.ConfigRealtimeHttpClient",
        "com.google.firebase.remoteconfig.internal.ConfigFetchHttpClient"
    ];

    firebaseClients.forEach(name => {
        try {
            const clazz = Java.use(name);
            clazz.getFingerprintHashForPackage.implementation = function () {
                return PACKAGE_SIGNATURE;          // <- fake hash
            };
        } catch (e) {
            console.warn("!!?  Can't hook " + name + ": " + e);
        }
    });

    /* 2??  Image-library "getPackageName" -> our package --------------------------------- */
    try {
        const ImgC = Java.use("ly.img.android.c");
        ImgC.d.implementation = function () {          // `d()` is the obfuscated getPackageName()
            return GRINDR_PACKAGE_NAME;
        };
    } catch (e) { console.warn("!!?  Can't hook ly.img.android.c.d(): " + e); }

    /* 3??  Facebook login -> always use webview --------------------------------------- */
    try {
        const FbKatana = Java.use("com.facebook.login.KatanaProxyLoginMethodHandler");
        // `tryAuthorize(request)` normally returns an int.  Returning 0 tells Facebook SDK
        // that the Facebook app was *not* started -> it will fall back to the web dialog.
        FbKatana.tryAuthorize.implementation = function (request) {
            // We don't care about the original return value, we always want 0
            return 0;
        };
    } catch (e) { console.warn("!!?  Can't hook Facebook Katana: " + e); }

    /* 4??  ContextWrapper.getPackageName - spoof when called from FirebaseInstallationServiceClient */
    try {
        const CtxWrapper = Java.use("android.content.ContextWrapper");

        CtxWrapper.getPackageName.implementation = function () {
            const pkg = this.getPackageName(); // original result

            // Determine if the call originates from FirebaseInstallationServiceClient
            const Thread = Java.use("java.lang.Thread");
            const stk = Thread.currentThread().getStackTrace();
            for (let i = 0; i < stk.length; i++) {
                if (stk[i].getClassName().startsWith(
                        "com.google.firebase.installations.remote.FirebaseInstallationServiceClient")) {
                    return GRINDR_PACKAGE_NAME; // spoofed
                }
            }
            return pkg;                     // otherwise leave unchanged
        };
    } catch (e) { console.warn("!!?  Can't hook ContextWrapper.getPackageName: " + e); }

    /* 5??  Firebase Messaging Metadata.getPackageInfo -> swap "grindr" -> real pkg */
    try {
        const Metadata = Java.use("com.google.firebase.messaging.Metadata");
        Metadata.getPackageInfo.overload('java.lang.String').implementation = function (pkgName) {
            if (pkgName.includes('grindr')) {
                pkgName = GRINDR_PACKAGE_NAME;
            }
            return this.getPackageInfo(pkgName);  // call the original with the (maybe) modified name
        };
    } catch (e) { console.warn("!!?  Can't hook Firebase Messaging Metadata.getPackageInfo: " + e); }

    /* --------------------------------------------------------------------------- */
    /* ====   HERE GOES THE REST OF YOUR "ANTIDETECTION" HOOKS THAT WE BUILT EARLIER  ==== */
    /* --------------------------------------------------------------------------- */

    // 1??  Fake Build constants
    const Build = Java.use('android.os.Build');
    Build.MODEL.value          = "Google Pixel 5";
    Build.PRODUCT.value        = "googlew";
    Build.DEVICE.value         = "googlew";
    Build.FINGERPRINT.value    = "google/wifi:10.0.1/ROM:12345:userdebug";
    Build.MANUFACTURER.value   = "Google";
    Build.BRAND.value          = "Google";
    Build.DISPLAY.value        = "PPIA.180815.006";
    Build.TYPE.value           = "user";
    Build.TAGS.value           = "release-keys";
    Build.VERSION.SDK_INT.value = 30;   // same as your real device

    // 2??  Fake serial
    Build.getSerial.implementation = function () { return "1234567890ABCDEF"; };

    // 3??  Fake System properties (ro.*, ro.build.*, persist.*)
    const Sys = Java.use('java.lang.System');
    const props = {
        "ro.hardware":          "samsung",
        "ro.product.model":     "SM-G991B",
        "ro.product.brand":     "Samsung",
        "ro.product.manufacturer":"Samsung",
        "ro.build.version.sdk": "30",
        "ro.build.version.release":"11",
        "ro.build.flavor":      "user",
        "ro.build.type":        "user",
        "ro.build.id":          "RQ3A.210605.001",
        "persist.sys.usb.config": "mtp,adb",
        "ro.build.product":     "googlew",
        "ro.build.id":          "RQ3A.210605.001",
    };
    Sys.getProperty.implementation = function (key) {
        if (props[key] != null) return props[key];
        return this.getProperty(key);
    };

    // 4??  Hide 'emulator' packages from PackageManager
    const PkgMgr = Java.use('android.content.pm.PackageManager');
    PkgMgr.getInstalledPackages.overload('int').implementation = function (flags) {
        const full = this.getInstalledPackages(flags);
        const filtered = Java.use('java.util.ArrayList').$new();

        const it = full.iterator();
        while (it.hasNext()) {
            const pkg = it.next();
            const name = pkg.packageName;
            if (!name.contains('genymotion') &&
                !name.contains('nox') &&
                !name.contains('virtualbox') &&
                !name.contains('blueStacks') &&
                !name.contains('ericsson') &&
                !name.contains('virtual') &&
                !name.contains('emulator')) {
                filtered.add(pkg);
            }
        }
        return filtered;
    };

    // 5??  Fake CommonUtils (FirebaseCrashlytics)
    const Common = Java.use('com.google.firebase.crashlytics.internal.common.CommonUtils');
    Common.isRooted.implementation   = function () { return false; };
    Common.isEmulator.implementation = function () { return false; };
    Common.isAppDebuggable.implementation = function () { return false; };

    // 6??  Fake DevicePropertiesCollector (siftscience SDK)
    const Dpc = Java.use('siftscience.android.DevicePropertiesCollector');
    Dpc.getSystemProperties.implementation = function () {
        const map = Java.use('java.util.HashMap').$new();
        map.put("model",      Build.MODEL.value);
        map.put("device",     Build.DEVICE.value);
        map.put("product",    Build.PRODUCT.value);
        map.put("manufacturer", Build.MANUFACTURER.value);
        map.put("fingerprint", Build.FINGERPRINT.value);
        map.put("serial",     Build.getSerial.call());
        map.put("brand",      Build.BRAND.value);
        map.put("display",    Build.DISPLAY.value);
        map.put("tags",       Build.TAGS.value);
        map.put("type",       Build.TYPE.value);
        map.put("os",         System.getProperty("os.name"));  // fallback
        return map;
    };
    Dpc.collect.implementation = function () { return this.getSystemProperties(); };

    // 7??  mg.n.O - obfuscated helper that Grindr uses
    const mgN = Java.use('mg.n');
    mgN.O.implementation = function () { return false; };

    // 8??  AutoValue_StaticSessionData_OsData constructor - force isRooted=false
    const OsData = Java.use('com.google.firebase.crashlytics.internal.model.AutoValue_StaticSessionData_OsData');
    const origCtor = OsData.$init;
    // Hook ALL overloads - we cannot know the exact signature, so the generic wrapper will do
    OsData.$init.implementation = function () {
        const args = Array.prototype.slice.call(arguments);
        if (args.length >= 3) args[2] = false;      // index?2 = isRooted
        return origCtor.apply(this, args);
    };

    console.log("[fullspoof] All spoof hooks installed. Grindr should now think it's a real phone.");
});
