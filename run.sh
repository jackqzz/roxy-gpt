#!/bin/sh
cd "$(dirname "$0")"
exec .venv/bin/python3 server.py
