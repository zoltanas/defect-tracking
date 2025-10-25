#!/bin/sh
export LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu/
exec gunicorn --bind 0.0.0.0:$PORT --workers 1 --threads 8 --timeout 0 app:app
