#!/usr/bin/env python3
import subprocess
import sys
import urllib.parse

files = [urllib.parse.unquote(f.replace('file://', '')) for f in sys.argv[1:]]
if files:
    subprocess.Popen(['clamguard', '--scan'] + files)
