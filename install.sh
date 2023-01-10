#!/bin/bash
pip install mongoengine
pip install django-mdeditor 
pip install Markdown
pip install Pygments

python3 manage.py migrate system ruleroam
python3 manage.py migrate

