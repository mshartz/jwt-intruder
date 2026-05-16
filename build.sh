#!/usr/bin/env bash
# ================================================================
# build.sh  –  builds jwt-intruder-all.jar
# Requirements: JDK 11+, curl
# Usage:  cd jwt-intruder && bash build.sh
# Output: dist/jwt-intruder-all.jar
# ================================================================
set -e
cd "$(dirname "$0")"
SCRIPT_DIR="$(pwd)"

echo "==> Project directory: $SCRIPT_DIR"

DEPS_DIR="$SCRIPT_DIR/.build/deps"
COMPILE_DIR="$SCRIPT_DIR/.build/compile"
EXTRACT_DIR="$SCRIPT_DIR/.build/extract"
DIST_DIR="$SCRIPT_DIR/dist"
SRC_DIR="$SCRIPT_DIR/src/main/java"
RES_DIR="$SCRIPT_DIR/src/main/resources"

if [ ! -d "$SRC_DIR" ]; then
  echo "ERROR: Cannot find source directory: $SRC_DIR"
  echo "Files present:"; ls "$SCRIPT_DIR"; exit 1
fi

mkdir -p "$DEPS_DIR" "$COMPILE_DIR" "$EXTRACT_DIR" "$DIST_DIR"

# ── Montoya API (compile-only, NOT bundled) ──────────────────────
MONTOYA_JAR="$DEPS_DIR/montoya-api.jar"
MONTOYA_URL="https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/2026.2/montoya-api-2026.2.jar"

if [ -f "$MONTOYA_JAR" ]; then
  SIZE=$(wc -c < "$MONTOYA_JAR")
  if [ "$SIZE" -lt 50000 ]; then
    echo "  [stale] Removing undersized montoya-api.jar ($SIZE bytes)"
    rm -f "$MONTOYA_JAR"
  else
    echo "  [cached] montoya-api.jar ($SIZE bytes)"
  fi
fi
if [ ! -f "$MONTOYA_JAR" ]; then
  echo "  [download] montoya-api-2026.2.jar"
  curl -fsSL "$MONTOYA_URL" -o "$MONTOYA_JAR"
fi

# ── Runtime dependencies (bundled into fat JAR) ──────────────────
NIMBUS_JAR="$DEPS_DIR/nimbus-jose-jwt-9.37.3.jar"
BCPROV_JAR="$DEPS_DIR/bcprov-jdk18on-1.77.jar"
BCPKIX_JAR="$DEPS_DIR/bcpkix-jdk18on-1.77.jar"
JSON_JAR="$DEPS_DIR/json-20240303.jar"
CONTENT_TYPE_JAR="$DEPS_DIR/content-type-2.3.jar"
JSON_SMART_JAR="$DEPS_DIR/json-smart-2.5.1.jar"
ACCESSORS_JAR="$DEPS_DIR/accessors-smart-2.5.1.jar"
ASM_JAR="$DEPS_DIR/asm-9.6.jar"

MAVEN="https://repo1.maven.org/maven2"

download() {
  local url="$1" dest="$2"
  if [ -f "$dest" ]; then echo "  [cached] $(basename "$dest")"
  else echo "  [download] $(basename "$dest")"; curl -fsSL "$url" -o "$dest"; fi
}

echo "==> Downloading dependencies..."
download "$MAVEN/com/nimbusds/nimbus-jose-jwt/9.37.3/nimbus-jose-jwt-9.37.3.jar"           "$NIMBUS_JAR"
download "$MAVEN/org/bouncycastle/bcprov-jdk18on/1.77/bcprov-jdk18on-1.77.jar"             "$BCPROV_JAR"
download "$MAVEN/org/bouncycastle/bcpkix-jdk18on/1.77/bcpkix-jdk18on-1.77.jar"             "$BCPKIX_JAR"
download "$MAVEN/org/json/json/20240303/json-20240303.jar"                                  "$JSON_JAR"
download "$MAVEN/com/nimbusds/content-type/2.3/content-type-2.3.jar"                       "$CONTENT_TYPE_JAR"
download "$MAVEN/net/minidev/json-smart/2.5.1/json-smart-2.5.1.jar"                        "$JSON_SMART_JAR"
download "$MAVEN/net/minidev/accessors-smart/2.5.1/accessors-smart-2.5.1.jar"              "$ACCESSORS_JAR"
download "$MAVEN/org/ow2/asm/asm/9.6/asm-9.6.jar"                                          "$ASM_JAR"

# ── Compile ──────────────────────────────────────────────────────
echo "==> Compiling sources..."
RUNTIME_CP="$NIMBUS_JAR:$BCPROV_JAR:$BCPKIX_JAR:$JSON_JAR:$CONTENT_TYPE_JAR:$JSON_SMART_JAR:$ACCESSORS_JAR:$ASM_JAR"
CP="$MONTOYA_JAR:$RUNTIME_CP"

find "$SRC_DIR" -name "*.java" | xargs javac \
  --release 11 \
  -cp "$CP" \
  -d "$COMPILE_DIR" 2>&1

echo "   Sources compiled OK."

# ── Assemble fat JAR (montoya-api intentionally excluded) ────────
echo "==> Assembling fat JAR..."
rm -rf "$EXTRACT_DIR" && mkdir -p "$EXTRACT_DIR"

for jar in "$NIMBUS_JAR" "$BCPROV_JAR" "$BCPKIX_JAR" "$JSON_JAR" \
           "$CONTENT_TYPE_JAR" "$JSON_SMART_JAR" "$ACCESSORS_JAR" "$ASM_JAR"; do
  (cd "$EXTRACT_DIR" && jar xf "$jar")
done

# Remove JAR signature files that break fat-jar loading
find "$EXTRACT_DIR/META-INF" \( -name "*.SF" -o -name "*.DSA" -o -name "*.RSA" \) \
     -delete 2>/dev/null || true

# Overlay compiled classes and resources
cp -r "$COMPILE_DIR/." "$EXTRACT_DIR/"
cp -r "$RES_DIR/."     "$EXTRACT_DIR/"

OUTPUT="$DIST_DIR/jwt-intruder-all.jar"
(cd "$EXTRACT_DIR" && jar cf "$OUTPUT" .)

echo ""
echo "✓  Build successful!"
echo "   Load in Burp Suite → Extensions → Add → Java:"
echo "   $OUTPUT"
