#!/bin/sh
set -e

# Set the library path directly
export LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu

# Execute the main container command
exec gunicorn --bind 0.0.0.0:$PORT --workers 1 --threads 8 --timeout 0 app:app
