#!/bin/bash

# Script to convert OpenAPI spec to Postman collection
# Usage: ./bin/build-postman.sh [output-file]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
OPENAPI_FILE="api/openapi.yml"
OUTPUT_FILE="${1:-postman-collection.json}"
BUNDLED_FILE="api/openapi-bundled.yml"

# Function to print colored messages
print_info() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Check if OpenAPI file exists
if [ ! -f "$OPENAPI_FILE" ]; then
    print_error "OpenAPI file not found: $OPENAPI_FILE"
    exit 1
fi

echo "=========================================="
echo "Building Postman Collection from OpenAPI"
echo "=========================================="
echo ""

# Step 1: Bundle OpenAPI spec (resolve $ref)
echo "Step 1: Bundling OpenAPI spec (resolving \$ref)..."

if command -v redocly &> /dev/null; then
    print_info "Using redocly to bundle OpenAPI spec..."
    redocly bundle "$OPENAPI_FILE" -o "$BUNDLED_FILE" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        print_info "OpenAPI spec bundled successfully"
        BUNDLED_SPEC="$BUNDLED_FILE"
    else
        print_warn "Failed to bundle with redocly, using original file"
        BUNDLED_SPEC="$OPENAPI_FILE"
    fi
else
    print_warn "redocly not found, using original OpenAPI file"
    print_warn "Note: Some \$ref may not be resolved correctly"
    BUNDLED_SPEC="$OPENAPI_FILE"
fi

echo ""

# Step 2: Check for openapi2postmanv2
echo "Step 2: Checking for openapi2postmanv2 converter..."

if ! command -v openapi2postmanv2 &> /dev/null; then
    print_warn "openapi2postmanv2 not found"
    echo ""
    echo "Installing openapi-to-postmanv2..."
    
    if command -v npm &> /dev/null; then
        npm install -g openapi-to-postmanv2
        if [ $? -eq 0 ]; then
            print_info "openapi-to-postmanv2 installed successfully"
        else
            print_error "Failed to install openapi-to-postmanv2"
            echo ""
            echo "Please install manually:"
            echo "  npm install -g openapi-to-postmanv2"
            exit 1
        fi
    else
        print_error "npm not found. Please install Node.js and npm first."
        echo ""
        echo "Then install openapi-to-postmanv2:"
        echo "  npm install -g openapi-to-postmanv2"
        exit 1
    fi
else
    print_info "openapi2postmanv2 found"
fi

echo ""

# Step 3: Convert to Postman collection
echo "Step 3: Converting OpenAPI to Postman collection..."

openapi2postmanv2 -s "$BUNDLED_SPEC" -o "$OUTPUT_FILE"

if [ $? -eq 0 ]; then
    print_info "Postman collection generated successfully: $OUTPUT_FILE"
else
    print_error "Failed to generate Postman collection"
    
    # Cleanup bundled file if it was created
    if [ -f "$BUNDLED_FILE" ] && [ "$BUNDLED_SPEC" = "$BUNDLED_FILE" ]; then
        rm -f "$BUNDLED_FILE"
    fi
    
    exit 1
fi

# Cleanup bundled file if it was created
if [ -f "$BUNDLED_FILE" ] && [ "$BUNDLED_SPEC" = "$BUNDLED_FILE" ]; then
    rm -f "$BUNDLED_FILE"
    print_info "Cleaned up temporary bundled file"
fi

echo ""
echo "=========================================="
print_info "Postman collection ready: $OUTPUT_FILE"
echo "=========================================="

