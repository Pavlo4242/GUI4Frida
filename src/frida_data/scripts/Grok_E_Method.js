Java.perform(function () {
    var ViewModel = Java.use("com.grindrapp.android.ui.browse.ServerDrivenCascadeViewModel");
    ViewModel.$init.implementation = function() {
        var ret = this.$init.apply(this, arguments);
        console.log("ViewModel constructed");
        var fields = this.getClass().getDeclaredFields();
        for (var i = 0; i < fields.length; i++) {
            var field = fields[i];
            field.setAccessible(true);
            var type = field.getType().getName();
            if (type.startsWith("com.grindrapp.android.ui.browse.")) {
                console.log("Found field: " + field.getName() + " of type " + type);
                // This type is the obfuscated E
            }
        }
        return ret;
    };
});