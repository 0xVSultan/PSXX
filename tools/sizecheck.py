#!/usr/bin/env python3
"""Fail the build if a PS-X EXE exceeds the memory-card payload budget (sec. 4/5)."""
import os, sys
path, limit = sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 100 * 1024
size = os.path.getsize(path)
print(f"{path}: {size} B / {limit} B")
sys.exit(1 if size > limit else 0)
