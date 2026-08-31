#!/usr/bin/env bash
# Corre el mismo análisis que la CI, en local.
# Requiere: pip install semgrep

set -e

semgrep scan \
  --config p/owasp-top-ten \
  --config p/security-audit \
  --config p/python \
  --config p/flask \
  .
