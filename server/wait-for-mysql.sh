#!/bin/sh
# wait-for-mysql.sh

echo "⏳ Waiting for MySQL to be ready..."
until nc -z -v -w30 $DB_HOST $DB_PORT
do
  echo "Waiting for MySQL at $DB_HOST:$DB_PORT..."
  sleep 5
done

echo "✅ MySQL is up. Starting backend..."
exec "$@"
