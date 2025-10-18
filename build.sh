#!/bin/bash

COMMIT_HASH=$(git rev-parse --short HEAD)

sed "s/app\.js/app.js?v=$COMMIT_HASH/g; s/styles\.css/styles.css?v=$COMMIT_HASH/g" index.html > index.tmp.html
mv index.tmp.html index.html

echo "Updated assets to version: $COMMIT_HASH"
