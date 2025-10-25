#!/bin/sh
set -e

# Read the library path from the file and export it
export LD_LIBRARY_PATH=$(cat /library_path.txt)
echo "LD_LIBRARY_PATH set to: $LD_LIBRARY_PATH"

# Execute the main container command
exec gunicorn --bind 0.0.0.0:$PORT --workers 1 --threads 8 --timeout 0 app:app
