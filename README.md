# Flutter GunGo 🥷🔫

A Go implementation of the popular reFlutter framework for reverse engineering Flutter applications. This tool helps analyze Flutter apps by patching the Flutter engine to enable dynamic analysis, traffic interception, and code dumping.

## Features

- **Cross-platform support**: Android (ARM64, ARM32) and iOS (ARM64)
- **Traffic monitoring**: Intercept and monitor network traffic without certificates
- **Code dumping**: Extract Dart classes, functions, and fields with absolute code offsets
- **Snapshot analysis**: Parse Flutter snapshot data for reverse engineering
- **Proxy integration**: Built-in support for Burp Suite and other proxy tools
- **Certificate pinning bypass**: Bypass some Flutter certificate pinning implementations
- **No root required**: Works on Android devices without root access

## Installation

### From Source
```bash
git clone https://github.com/CreamyMilk/flutter-gun-go
cd flutter-gun-go
go build -o reflutter ./cmd/reflutter
```

### Using Go Install
```bash
go install github.com/CreamyMilk/flutter-gun-go/cmd/reflutter@latest
```

## Quick Start

### Android APK Analysis
```bash
# Patch an APK file
reflutter patch --input app.apk --burp-ip 192.168.1.100

# The tool will output: app.RE.apk
# Sign the APK before installation
reflutter sign --input app.RE.apk --output app.signed.apk
```

### iOS IPA Analysis
```bash
# Patch an IPA file
reflutter patch --input app.ipa --burp-ip 192.168.1.100

# The patched IPA is ready for installation
```

## Usage

### Basic Commands

```bash
# Patch a Flutter app
reflutter patch [options] <input_file>

# Sign an APK (Android only)
reflutter sign --input <apk_file> --output <signed_apk>

# Extract snapshot information
reflutter analyze --input <app_file>

# Dump runtime information
reflutter dump --package <package_name> --output <dump_file>
```

### Configuration Options

```bash
# Specify Burp Suite proxy IP
reflutter patch --burp-ip 192.168.1.100 --burp-port 8083 app.apk

# Enable verbose output
reflutter patch --verbose app.apk

# Specify architecture (for multi-arch apps)
reflutter patch --arch arm64 app.apk

# Custom output directory
reflutter patch --output ./patched/ app.apk
```

## Proxy Setup

### Burp Suite / Proxyman Configuration
1. Navigate to **Proxy** → **Options** → **Proxy Listeners**
2. Add a new listener on port `8083`
3. Bind to address: **All interfaces**
4. In **Request handling** tab, enable **Support invisible proxying**

## Code Dumping

After running the patched application on the device, retrieve the dump file:

### Android
```bash
adb shell "cat /data/data/<PACKAGE_NAME>/dump.dart" > dump.dart
```

### iOS
Check Xcode console logs for the dump file path:
```
Current working dir: /private/var/mobile/Containers/Data/Application/<UUID>/dump.dart
```

### Dump File Format
```dart
Library:'package:myapp/auth/AuthService.dart' Class: AuthService extends Object {
    String* apiKey = "secret_key_here";
    Function 'authenticate': (String, String) => Future<bool> {
        Code Offset: _kDartIsolateSnapshotInstructions + 0x0000000000123456
    }
    Function 'validateToken': (String) => bool {
        Code Offset: _kDartIsolateSnapshotInstructions + 0x0000000000789abc
    }
}
```

## Advanced Usage

### Custom Engine Patches
```bash
# Apply custom patches to Flutter engine
reflutter build-engine --commit d44b5a94c976 --hash aa64af18e7d0 --patches ./my-patches/
```

### Frida Integration
Use the generated offsets with Frida for dynamic analysis:
```javascript
// frida-script.js
const baseAddr = Module.findBaseAddress("libapp.so");
const targetOffset = 0x123456; // From dump.dart
const targetAddr = baseAddr.add(targetOffset);

Interceptor.attach(targetAddr, {
    onEnter: function(args) {
        console.log("Function called with args:", args);
    }
});
```

## Security Considerations
- This tool is intended for authorized security testing and research only 😉

## Credits
- Original reFlutter framework by [Impact-I](https://github.com/Impact-I/reFlutter)
- Flutter team for the open-source Flutter framework

## Related Projects
- [Original reFlutter](https://github.com/Impact-I/reFlutter) - Python implementation
- [Blutter](https://github.com/worawit/blutter) - Flutter mobile app reverse engineering
- [Darter](https://github.com/mildsunrise/darter) - Dart snapshot parser