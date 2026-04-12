#!/bin/sh
set -e

if [ ! -d "node_modules" ] || [ ! -f "node_modules/.bin/react-scripts" ]; then
    echo "Installing dependencies..."
    npm config set proxy http://10.30.240.13:3128
    npm config set https-proxy http://10.30.240.13:3128
    npm install
fi

exec "$@"
