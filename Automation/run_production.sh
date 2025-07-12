#!/bin/bash
# this is to run the system in proudction mode
# Define the absolute path to your Automation folder
AUTOMATION_DIR="/Automation"

# Activate the virtual environment (use the correct path)
source "$AUTOMATION_DIR/bin/activate"

# Run the Django server with SSL
gunicorn --chdir $AUTOMATION_DIR ActiveDefense.wsgi:application

exit 0
