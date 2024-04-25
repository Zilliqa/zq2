#! /bin/bash

npm install
npm run assets-start
exec npx vite --port $PORT
