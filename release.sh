#!/usr/bin/env sh

# find . -name "*.pyc" -exec rm -f {} \;
python manage.py makemigrations babysitter_app
python manage.py migrate
echo "migrations have been completed"