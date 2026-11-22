#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
command -v eas >/dev/null 2>&1 || { echo "缺少 eas-cli：npm install -g eas-cli" >&2; exit 1; }

if ! eas whoami >/dev/null 2>&1; then
  echo "请先运行 eas login 登录自己的 Expo 账号。" >&2
  exit 1
fi

for app in admin user; do
  echo "=== Building iOS IPA: $app ==="
  (cd "$ROOT/apps/$app" && eas build --platform ios --profile preview)
done
