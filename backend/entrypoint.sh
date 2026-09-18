#!/usr/bin/env sh
set -eu
exec pqctool serve --host 0.0.0.0 --port "${PORT:-8000}"
