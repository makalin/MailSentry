#!/bin/bash
echo "Setting up MailSentry..."
conda deactivate
pyenv shell 3.11.0
python3 -m venv mailsentry_env
source mailsentry_env/bin/activate
pip install dnspython flask
python3 mailsch.py