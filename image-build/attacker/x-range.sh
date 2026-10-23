#!/bin/sh
# TinyCore executes files in ~/.X.d after the real X server starts.
if command -v dillo-beta >/dev/null 2>&1; then
  dillo-beta http://127.0.0.1:8081/ >/tmp/range-dillo.log 2>&1 &
elif command -v dillo >/dev/null 2>&1; then
  dillo http://127.0.0.1:8081/ >/tmp/range-dillo.log 2>&1 &
fi
