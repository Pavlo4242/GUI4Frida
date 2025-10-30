 spyemulator.js - put in the same directory as your hook file */
Java.perform(function () {
    /* === 1??  Utility to wrap any method with logging ---------------------------- */
    function logMethod(clazz, methodName, signature, prelog, postlog) {
        try {
            const mdl = signature
                ? clazz[methodName].overload.apply(clazz[methodName], signature)
                : clazz[methodName];

            mdl.implementation = function () {
                const args = Array.prototype.slice.call(arguments);

                // prelog (before the original runs)
                if (prelog) prelog(args);

                // run the real method
                const result = mdl.call(this, ...args);

                // postlog (after the original)
                if (postlog) postlog(result, args);

                return result;
            };
            console.log(`[spy] ${clazz.name}.${methodName} hooked`);
        } catch (e) {
            console.warn(`[spy] failed to hook ${clazz.name}.${methodName}: ${e}`);
        }
    }

    /* === 2??  Hook Build static fields (the most common culprit) --------------- */
    const Build = Java.use('android.os.Build');

    // These are *static* fields.  Read *after* the app has read them.
    // Log the value that the app sees each time it queries the field.
    logMethod(Build, 'MODEL', null,
        () => console.log(`[Build] MODEL queried before: ${Build.MODEL.value}`),
        (res) => console.log(`[Build] MODEL result: ${res}`));

    logMethod(Build, 'PRODUCT', null,
        () => console.log(`[Build] PRODUCT queried before: ${Build.PRODUCT.value}`),
        (res) => console.log(`[Build] PRODUCT result: ${res}`));

    logMethod(Build, 'FINGERPRINT', null,
        () => console.log(`[Build] FINGERPRINT queried before: ${Build.FINGERPRINT.value}`),
        (res) => console.log(`[Build] FINGERPRINT result: ${res}`));

    logMethod(Build, 'MANUFACTURER', null,
        () => console.log(`[Build] MANUFACTURER queried before: ${Build.MANUFACTURER.value}`),
        (res) => console.log(`[Build] MANUFACTURER result: ${res}`));

    logMethod(Build, 'BRAND', null,
        () => console.log(`[Build] BRAND queried before: ${Build.BRAND.value}`),
        (res) => console.log(`[Build] BRAND result: ${res}`));

    logMethod(Build, 'SERIAL', null,
        () => console.log(`[Build] SERIAL queried before: ${Build.SERIAL.value}`),
        (res) => console.log(`[Build] SERIAL result: ${res}`));

    /* === 3??  Hook common utilities that return "isEmulator", "isRooted"? ------ */
    const Common = Java.use('com.google.firebase.crashlytics.internal.common.CommonUtils');
    logMethod(Common, 'isRooted', null,
        () => console.log('[Common] isRooted queried before'),
        (res) => console.log(`[Common] isRooted result: ${res}`));

    logMethod(Common, 'isEmulator', null,
        () => console.log('[Common] isEmulator queried before'),
        (res) => console.log(`[Common] isEmulator result: ${res}`));

    logMethod(Common, 'isAppDebuggable', null,
        () => console.log('[Common] isAppDebuggable queried before'),
        (res) => console.log(`[Common] isAppDebuggable result: ${res}`));

    /* === 4??  Hook the DevicePropertiesCollector (sift science) ----------------- */
    const Dpc = Java.use('siftscience.android.DevicePropertiesCollector');
    logMethod(Dpc, 'existingRootPackages', null,
        () => console.log('[Dpc] existingRootPackages queried before'),
        (res) => console.log(`[Dpc] existingRootPackages result size: ${res.size()}`));
    // ? add any other method you suspect is part of the detection

    /* === 5??  Hook any native helper that looks at ro.* system properties ----- */
    const SysProp = Java.use('android.os.SystemProperties');
    logMethod(SysProp, 'get', ['java.lang.String'],
        (args) => console.log(`[SysProps] SystemProperties.get('${args[0]}') called`),
        (res, args) => console.log(`[SysProps] returned ${res} for key ${args[0]}`));

    /* === 6??  Hook the PackageManager - see which package list it returns -------- */
    const PM = Java.use('android.content.pm.PackageManager');
    logMethod(PM, 'getInstalledPackages', ['int'],
        () => console.log(`[PM] getInstalledPackages called`),
        (res, args) => console.log(`[PM] returned ${res.size()} packages`));
});
