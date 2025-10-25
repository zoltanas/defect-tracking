#!/bin/sh
set -e

echo "Running database initialization..."
flask init-db
echo "Database initialization complete."

# Execute the command passed as arguments to this script
exec "$@"
