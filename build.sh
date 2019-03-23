set -e

cd bridge-x86 && PATH="/Users/fluxxu/Projects/android-rust/NDK/x86/bin:$PATH" cargo build --target i686-linux-android $1 && cd ..
cd bridge-arm && cargo build --target armv7-linux-androideabi $1 && cd ..
PATH="/Users/fluxxu/Projects/android-rust/NDK/x86/bin:$PATH" cargo build --target i686-linux-android --features "android" $1