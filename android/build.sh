#!/bin/bash
# build shadowsocks-android plugin apk (arm64-v8a only)
# env: ANDROID_HOME, ANDROID_NDK_HOME
# optional env: VERSION_NAME, VERSION_CODE, KEYSTORE (base64), KEYSTORE_PASSWORD, KEY_ALIAS
set -euo pipefail

API=21
TARGET_API=37
ABI=arm64-v8a

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=$ROOT/build-android
DEPS=${DEPS:-$OUT/deps}
JOBS=$(nproc 2>/dev/null || sysctl -n hw.ncpu)

case "$(uname -s)" in
    Linux) HOST=linux-x86_64 ;;
    Darwin) HOST=darwin-x86_64 ;;
esac
TOOLCHAIN=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST
export PATH=$TOOLCHAIN/bin:$PATH
BUILD_TOOLS=$(ls -d "$ANDROID_HOME"/build-tools/* | sort -V | tail -1)
ANDROID_JAR=$ANDROID_HOME/platforms/android-$TARGET_API.0/android.jar

CMAKE_ANDROID=(
    -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake"
    -DANDROID_ABI=$ABI
    -DANDROID_PLATFORM=$API
    -DCMAKE_BUILD_TYPE=Release
)

# https://github.com/openssl/openssl/issues/18561
ANDROID_NDK_ROOT=$ANDROID_NDK_HOME "$ROOT/deps/openssl.sh" "$OUT" "$DEPS" \
    android-arm64 -U__ANDROID_API__ -D__ANDROID_API__=$API
"$ROOT/deps/libevent.sh" "$OUT" "$DEPS" "${CMAKE_ANDROID[@]}"

cmake -S "$ROOT" -B "$OUT/wss-proxy" "${CMAKE_ANDROID[@]}" \
    -DCMAKE_FIND_ROOT_PATH="$DEPS" \
    -DCMAKE_DISABLE_FIND_PACKAGE_PkgConfig=ON \
    -DOPENSSL_ROOT_DIR="$DEPS" \
    -DOPENSSL_USE_STATIC_LIBS=ON
cmake --build "$OUT/wss-proxy" --target wss-proxy-client -j"$JOBS"

APK=$OUT/apk
APK_FILE=$OUT/wss-proxy-client-${VERSION_NAME:-0.0.0}-$ABI.apk
rm -rf "$APK"
mkdir -p "$APK/lib/$ABI" "$APK/classes" "$APK/dex"
llvm-strip -o "$APK/lib/$ABI/libwss-proxy.so" "$OUT/wss-proxy/wss-proxy-client"

javac --release 8 -classpath "$ANDROID_JAR" -d "$APK/classes" \
    $(find "$ROOT/android/src" -name '*.java')
"$BUILD_TOOLS/d8" --release --min-api $API --lib "$ANDROID_JAR" --output "$APK/dex" \
    $(find "$APK/classes" -name '*.class')

"$BUILD_TOOLS/aapt2" link -o "$APK/unsigned.apk" -I "$ANDROID_JAR" \
    --manifest "$ROOT/android/AndroidManifest.xml" \
    --min-sdk-version $API --target-sdk-version $TARGET_API \
    --version-code "${VERSION_CODE:-1}" --version-name "${VERSION_NAME:-0.0.0}"
(cd "$APK/dex" && zip -q "$APK/unsigned.apk" classes.dex)
(cd "$APK" && zip -q -r unsigned.apk lib)
"$BUILD_TOOLS/zipalign" -f -P 16 4 "$APK/unsigned.apk" "$APK/aligned.apk"

if [ -n "${KEYSTORE:-}" ]; then
    echo "$KEYSTORE" | base64 -d > "$APK/release.jks"
else
    echo "KEYSTORE is not set, sign with a temporary key"
    export KEYSTORE_PASSWORD=android
    KEY_ALIAS=wss-proxy
    keytool -genkeypair -keystore "$APK/release.jks" -storepass $KEYSTORE_PASSWORD \
        -alias $KEY_ALIAS -keyalg RSA -keysize 2048 -validity 10000 -dname CN=wss-proxy
fi
"$BUILD_TOOLS/apksigner" sign --ks "$APK/release.jks" --ks-pass env:KEYSTORE_PASSWORD \
    --ks-key-alias "${KEY_ALIAS:-wss-proxy}" --out "$APK_FILE" "$APK/aligned.apk"
rm -f "$APK/release.jks"
"$BUILD_TOOLS/apksigner" verify "$APK_FILE"
echo "$APK_FILE"
