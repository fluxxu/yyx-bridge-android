set -e
./build.sh
adb push bridge-x86/target/i686-linux-android/debug/libbridge_x86.so /vendor/libyyxbridge_x86.so
adb push bridge-arm/target/armv7-linux-androideabi/debug/libbridge_arm.so /vendor/libyyxbridge_arm.so
adb push target/i686-linux-android/debug/yyx-bridge-android /vendor/yyx-bridge-android
adb shell chmod +x /vendor/yyx-bridge-android
adb shell /vendor/yyx-bridge-android