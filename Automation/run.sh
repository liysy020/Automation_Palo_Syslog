#!/bin/bash

# Define the absolute path to your Automation folder
AUTOMATION_DIR="/Automation"

# Activate the virtual environment (use the correct path)
source "$AUTOMATION_DIR/bin/activate"

# Run the Django server with SSL
python3 "$AUTOMATION_DIR/manage.py" runsslserver --certificate "$AUTOMATION_DIR/Cert/server.crt" --key "$AUTOMATION_DIR/Cert/server.key" 0.0.0.0:8000

exit 0
