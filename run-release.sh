set -e
./build-release.sh
adb push target/i686-linux-android/release/yyx-bridge-android /vendor/yyx-bridge-android
adb shell chmod +x /vendor/yyx-bridge-android
adb shell /vendor/yyx-bridge-android