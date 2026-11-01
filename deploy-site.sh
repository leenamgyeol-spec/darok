#!/bin/sh
# 알록다록 사이트를 https://allokdarok.darok.workers.dev 에 올림. 사용: sh deploy-site.sh
set -e
cd "$(dirname "$0")"
rm -rf site/public && mkdir -p site/public
cp index.html icon-180.png icon-512.png favicon-64.png site/public/
cd site && npx --yes wrangler@4 deploy
