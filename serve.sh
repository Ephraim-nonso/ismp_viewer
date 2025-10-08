#!/bin/bash
# Helper script to serve the ISMP Viewer app

echo "🚀 Starting ISMP Viewer..."
echo "📦 Building and serving with Trunk..."
echo ""

# Clear NO_COLOR environment variable that causes issues with trunk
env -u NO_COLOR trunk serve --open

# Alternative: If trunk serve doesn't work, use this:
# env -u NO_COLOR trunk build && python3 -m http.server --directory dist 8080

