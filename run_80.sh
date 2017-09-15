#!/bin/bash

sudo -u autoids FLASK_APP=/opt/autoIDSserver/main.py authbind flask run --port=80 --host=0.0.0.0
