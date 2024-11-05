#! /bin/bash

npm install
if [ -x "scripts/gen-version.sh" ]; then
    ./scripts/gen-version.sh autogen/version.ts
fi
npm run assets-start
exec npx vite --port $PORT
