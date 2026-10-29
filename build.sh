#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
#  Сборка Happ VPN Client → APK одной командой на Kali Linux / Debian
#  Использование:  ./build.sh
#  Результат:      app/build/outputs/apk/release/app-release.apk
# ═══════════════════════════════════════════════════════════════════════
set -e
cd "$(dirname "$0")"

echo "[*] Happ VPN Client — сборка APK"

# ── 1. Java 17 ────────────────────────────────────────────────────────
if ! command -v java >/dev/null 2>&1; then
    echo "[!] Java не найден. Устанавливаю OpenJDK 17..."
    sudo apt update && sudo apt install -y openjdk-17-jdk-headless
fi

JAVA_MAJOR=$(java -version 2>&1 | head -1 | grep -oP '"\K[0-9]+' | head -1)
if [ "${JAVA_MAJOR:-0}" -lt 17 ]; then
    echo "[!] Нужен Java >= 17 (найдена $JAVA_MAJOR). Устанавливаю..."
    sudo apt update && sudo apt install -y openjdk-17-jdk-headless
    export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
fi

# ── 2. Android SDK ────────────────────────────────────────────────────
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/android-sdk}}"
export ANDROID_HOME="$SDK"

CMDLINE="$SDK/cmdline-tools/latest"
if [ ! -x "$CMDLINE/bin/sdkmanager" ]; then
    echo "[*] Скачиваю Android command line tools..."
    mkdir -p "$SDK"
    TMP=$(mktemp -d)
    curl -fsSL -o "$TMP/cmdtools.zip" \
        https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip
    python3 -m zipfile -e "$TMP/cmdtools.zip" "$TMP/x" 2>/dev/null || unzip -q "$TMP/cmdtools.zip" -d "$TMP/x"
    mkdir -p "$SDK/cmdline-tools"
    rm -rf "$CMDLINE"
    mv "$TMP/x/cmdline-tools" "$CMDLINE"
    chmod +x "$CMDLINE/bin/"*
    rm -rf "$TMP"
fi

echo "[*] Проверяю лицензии SDK..."
yes | "$CMDLINE/bin/sdkmanager" --licenses >/dev/null 2>&1 || true

echo "[*] Устанавливаю platform-tools, android-34, build-tools 34.0.0..."
"$CMDLINE/bin/sdkmanager" "platform-tools" "platforms;android-34" "build-tools;34.0.0" >/dev/null

# ── 3. Gradle ─────────────────────────────────────────────────────────
if ! command -v gradle >/dev/null 2>&1; then
    GRADLE_HOME="$HOME/gradle-8.7"
    if [ ! -x "$GRADLE_HOME/bin/gradle" ]; then
        echo "[*] Скачиваю Gradle 8.7..."
        TMP=$(mktemp -d)
        curl -fsSL -o "$TMP/gradle.zip" https://services.gradle.org/distributions/gradle-8.7-bin.zip
        python3 -m zipfile -e "$TMP/gradle.zip" "$TMP/x" 2>/dev/null || unzip -q "$TMP/gradle.zip" -d "$TMP/x"
        rm -rf "$GRADLE_HOME"
        mv "$TMP/x/gradle-8.7" "$GRADLE_HOME"
        chmod +x "$GRADLE_HOME/bin/gradle"
        rm -rf "$TMP"
    fi
    export PATH="$GRADLE_HOME/bin:$PATH"
fi

# ── 4. Ключ подписи (создаётся автоматически, если отсутствует) ───────
KEYSTORE="release.keystore"
KS_PASS="happvpn"
if [ ! -f "$KEYSTORE" ]; then
    echo "[*] Создаю ключ подписи release.keystore (пароль: happvpn)..."
    keytool -genkeypair -v -keystore "$KEYSTORE" -alias happvpn \
        -keyalg RSA -keysize 2048 -validity 10000 \
        -storepass "$KS_PASS" -keypass "$KS_PASS" \
        -dname "CN=HappVPNClient, OU=Dev, O=HappVPN, L=Local, S=Local, C=RU"
fi

# ── 5. Сборка ─────────────────────────────────────────────────────────
echo "[*] Запускаю gradle assembleRelease..."
gradle --no-daemon assembleRelease \
    -Pandroid.injected.signing.store.file="$(pwd)/$KEYSTORE" \
    -Pandroid.injected.signing.store.password="$KS_PASS" \
    -Pandroid.injected.signing.key.alias=happvpn \
    -Pandroid.injected.signing.key.password="$KS_PASS"

APK="app/build/outputs/apk/release/app-release.apk"
if [ -f "$APK" ]; then
    cp "$APK" happ-vpn-client.apk
    echo ""
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║  ГОТОВО! APK собран:                                    ║"
    echo "║    $(realpath happ-vpn-client.apk)"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo "[i] Установка на устройство через adb:  adb install happ-vpn-client.apk"
else
    echo "[!] Сборка завершилась без APK — смотрите лог выше"
    exit 1
fi
