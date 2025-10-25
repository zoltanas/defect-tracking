#!/bin/sh
set -e

# Execute the main container command
exec gunicorn --bind 0.0.0.0:$PORT --workers 1 --threads 8 --timeout 0 app:app
