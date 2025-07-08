#!/bin/bash

# Define the absolute path to your Automation folder
AUTOMATION_DIR="/Automation"

# Activate the virtual environment (use the correct path)
source "$AUTOMATION_DIR/bin/activate"

# Run the Django server with SSL
python3 "$AUTOMATION_DIR/manage.py" runserver 127.0.0.1:8000

exit 0
