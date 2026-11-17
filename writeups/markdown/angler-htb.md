# Angler — HTB (Android Reversing)

**Angler** is a Hack The Box Android challenge. The app hides its flag behind a broadcast receiver and a native library, and dares you to "look me inside." The intended path is pure dynamic instrumentation: trigger the hidden code path, hook the Java decoder with Frida, then drop to the native layer and hook `strcmp` to catch the flag as it's compared.

> **Platform:** Hack The Box · **Category:** Mobile Security · **Tools:** jadx, Frida, adb

## Recon — the manifest

Decompiling the APK, the manifest shows an exported `MainActivity` and, more interestingly, the app registers a receiver at runtime rather than declaring a juicy component statically:

```xml
<activity android:name="com.example.angler.MainActivity" android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
</activity>
```

In `onCreate`, the app wires a receiver to the **low-battery** system broadcast:

```java
registerReceiver(this.f1756z, new IntentFilter("android.intent.action.BATTERY_LOW"));
```

## The hidden code path

The receiver only does something interesting when the intent carries an extra `Is_on == "yes"`. That branch calls a native method `getInfo()` with the result of a Java decoder `d.d("XDR")`:

```java
public final void onReceive(Context context, Intent intent) {
    if (intent.getStringExtra("Is_on").equals("yes")) {
        // ...updates the UI to the "1%" / "Please don't kill me" screen...
        Toast.makeText(context, "Look me inside", 1).show();
        System.out.println(MainActivity.this.getInfo(d.d("XDR")));
    } else {
        System.out.println("I am Strong, no one can defeat me");
    }
}
```

So two things decide the flag path: the `Is_on=yes` extra, and whatever `d.d()` and the native `getInfo()` actually do.

## Triggering it with adb

I fired the broadcast manually with the required extra:

```bash
adb shell am broadcast -a android.intent.action.BATTERY_LOW --es Is_on yes --include-stopped-packages
```

The UI flips to the challenge's "1% — Please don't kill me! I'll tell you where the flag is." screen, confirming the branch ran:

![Angler app after triggering the low-battery broadcast](writeups/images/angler-app.jpg)

## Hooking the Java decoder with Frida

`d.d()` is clearly a string transform. Rather than reverse it statically, I hooked it and watched the inputs/outputs live:

```javascript
Java.perform(function () {
    var dClass = Java.use('s.d');
    dClass.d.overload('java.lang.String').implementation = function (arg) {
        console.log('d.d called with argument: ' + arg);
        var result = this.d(arg);
        console.log('d.d returned: ' + result);
        return result;
    };
});
```

```bash
frida -U -p 5032 -l ../frida-scripts/angler.js
```

![Hooking d.d() — "XDR" decodes to "HTB"](writeups/images/angler-dd-hook.jpg)

The log shows the obfuscated UI string being decoded, and then `d.d("XDR")` returning **`HTB`** — so `"HTB"` is what gets passed into the native `getInfo()`.

## Dropping to native — hooking strcmp

`getInfo()` lives in `libangler.so`, so the comparison that gates the flag happens in native code. Instead of disassembling the library, I hooked libc's `strcmp` and logged every pair of strings it compared:

```javascript
var strcmpPtr = Module.findExportByName(null, "strcmp");
Interceptor.attach(strcmpPtr, {
    onEnter: function (args) {
        var str1 = Memory.readUtf8String(args[0]);
        var str2 = Memory.readUtf8String(args[1]);
        console.log("strcmp called with strings:", str1, str2);
    }
});
```

```bash
frida -U -p 5032 -l ../frida-scripts/flag_angler.js
```

Amid the noise, the native code compares `HTB` against a long hex blob:

![strcmp leaking the flag as hex](writeups/images/angler-strcmp.jpg)

```text
strcmp called with strings: HTB 4854427b796f755f3472335f676f6f645f34745f6830306b316e397d
```

## Decoding the flag

That hex is just ASCII:

```bash
echo "4854427b796f755f3472335f676f6f645f34745f6830306b316e397d" | xxd -r -p
HTB{you_4r3_good_4t_h00k1n9}
```

> **HTB{you_4r3_good_4t_h00k1n9}**

## Takeaways

- **Runtime beats static when logic is small.** Hooking `d.d()` and `strcmp` recovered the whole secret without ever disassembling `libangler.so`.
- **`strcmp` is a gift.** Native checks that compare secrets with libc string functions leak those secrets to anyone who can attach an instrumentation engine — a reminder that client-side secrets in a mobile app are never really secret.
- **Hidden triggers aren't protection.** Gating behaviour behind an obscure broadcast (`BATTERY_LOW` + a magic extra) only slows down a tester with `adb`; it isn't a security control.

**Tooling:** jadx for decompilation, Frida 16 for Java + native hooking, adb for broadcasting the intent, a rooted Pixel emulator running `frida-server`.
