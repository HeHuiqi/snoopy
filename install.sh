#!/bin/bash
pip install mongoengine
pip install django-mdeditor 
pip install Markdown
pip install Pygments

python3 manage.py makemigrations
python3 manage.py migrate

python3 manage.py runserver
