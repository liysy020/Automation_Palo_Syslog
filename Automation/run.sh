#!/bin/bash

# Define the absolute path to your Automation folder
AUTOMATION_DIR="/Automation"
source "$AUTOMATION_DIR/bin/activate"
"$AUTOMATION_DIR/bin/gunicorn" ActiveDefense.wsgi:application --bind 127.0.0.1:8000 --timeout 600

exit 0
