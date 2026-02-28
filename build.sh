#!/bin/bash

# Build script for FuzzMind Burp Extension

BUILD_DIR="build"
CLASSES_DIR="$BUILD_DIR/classes"
JAR_FILE="$BUILD_DIR/FuzzMind.jar"
ORIGINAL_JAR="FuzzMind_original.jar"
SRC_DIR="src/main/java"
LIBS_DIR="$BUILD_DIR/libs"

# Clean previous build
rm -rf "$BUILD_DIR"
mkdir -p "$CLASSES_DIR"
mkdir -p "$LIBS_DIR"

# Extract original JAR dependencies
echo "Extracting dependencies from original JAR..."
unzip -o "$ORIGINAL_JAR" -d "$BUILD_DIR/original_jar" > /dev/null 2>&1

# Copy required libraries (only org directory for dependencies like json, yaml)
# For Burp interfaces, we only need the I* classes for compilation
# Do NOT copy all burp classes - our burp classes are freshly compiled
echo "Copying dependencies..."
cp -r "$BUILD_DIR/original_jar/org" "$LIBS_DIR/" 2>/dev/null

# Create burp directory for Burp Suite interfaces only (needed for compilation)
mkdir -p "$LIBS_DIR/burp"
for iface in "$BUILD_DIR/original_jar/burp"/I*.class; do
    cp "$iface" "$LIBS_DIR/burp/" 2>/dev/null
done

# Collect all Java source files
echo "Collecting Java source files..."
SOURCES=$(find "$SRC_DIR" -name "*.java")

# Compile all Java files with proper classpath
echo "Compiling Java files..."
javac -d "$CLASSES_DIR" -cp "$LIBS_DIR" $SOURCES 2>&1 | tee "$BUILD_DIR/compile.log"

# Check if compilation succeeded
if [ ${PIPESTATUS[0]} -ne 0 ]; then
    echo "Compilation failed! Check compile.log for details."
    cat "$BUILD_DIR/compile.log"
    exit 1
fi

echo "Compilation successful!"

# Create manifest
echo "Creating manifest..."
mkdir -p "$BUILD_DIR/META-INF"
cat > "$BUILD_DIR/META-INF/MANIFEST.MF" << 'EOF'
Manifest-Version: 1.0
Created-By: FuzzMind Build Script
EOF

# Build JAR with compiled classes
echo "Building JAR file..."
cd "$CLASSES_DIR"
jar cfm "../FuzzMind.jar" "../META-INF/MANIFEST.MF" .
cd - > /dev/null

# Add dependencies to JAR (only org directory for external libraries)
echo "Adding dependencies to JAR..."
cd "$LIBS_DIR"
jar uf "../FuzzMind.jar" org 2>/dev/null
cd - > /dev/null

# Verify JAR exists
echo ""
if [ -f "$JAR_FILE" ]; then
    echo "Build completed successfully!"
    echo "Output: $JAR_FILE"
    echo ""
    ls -la "$JAR_FILE"
    echo ""
    echo "JAR contents (burp classes):"
    jar tf "$JAR_FILE" | grep "^burp/.*\.class$" | head -20
else
    echo "Build failed! JAR file not found."
    exit 1
fi
