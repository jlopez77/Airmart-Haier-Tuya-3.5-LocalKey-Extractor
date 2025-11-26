// hook_localkeys.js
Java.perform(function () {
    var targetClasses = [
        "com.thingclips.smart.device.bean.DeviceBean",
        "com.thingclips.sdk.device.bean.DeviceBean",
        "com.tuya.smart.device.bean.DeviceBean",
    ];

    function log(msg) {
        console.log("[KEY] " + msg);
    }

    targetClasses.forEach(function (clsName) {
        try {
            var Cls = Java.use(clsName);

            if (Cls.getLocalKey) {
                Cls.getLocalKey.implementation = function () {
                    var key = this.getLocalKey();
                    var id = "";

                    try {
                        id = this.getDevId();
                    } catch (e) { }

                    log(id + " = " + key);
                    return key;
                };

                log("Hooked " + clsName + ".getLocalKey()");
            }
        } catch (e) {}
    });
});
