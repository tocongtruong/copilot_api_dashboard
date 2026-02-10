#!/bin/sh
if [ "$1" = "--auth" ]; then
  exec bun run dist/main.js auth
elif [ -n "$GH_TOKEN" ] && [ "$GH_TOKEN" != "your_github_token_here" ]; then
  exec bun run dist/main.js start -g "$GH_TOKEN" "$@"
else
  echo "No GitHub token configured. Starting in token-waiting mode..."
  echo "Use the dashboard to add a GitHub token and activate it."
  exec bun run dist/main.js start "$@"
fi

