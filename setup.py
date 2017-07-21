#!/usr/bin/env python2
from config import *
import pwd
import argparse
import subprocess

# todo: check for presence of flask

parser = argparse.ArgumentParser(description='autoIDSserver setup script, assumes root privs')
parser.add_argument('-u','--unprivileged',help='run as unpriv\'d user specified in config.py',action='store_true',required=False)
args = parser.parse_args()

subprocess.call('sudo apt-get install -y python-pip python-setuptools apache2', shell=True)
subprocess.call('sudo pip install --upgrade pip flask pygments peewee', shell=True)
subprocess.call('sed -i \'s/<VirtualHost \*:80>/<VirtualHost \*:81>/g\' /etc/apache2/sites-enabled/000-default.conf', shell=True)

if args.unprivileged:
    try:
        pwd.getpwnam(UNPRIV_USER)
    except KeyError:
        print 'UNPRIV_USER does not exist, creating...'
        subprocess.call('useradd -s /bin/false ' + UNPRIV_USER, shell=True)
        subprocess.call('echo \'' + UNPRIV_USER + ':' + UNPRIV_PASS + '\' | sudo chpasswd ', shell=True)
else:
    input('Warning: is not suggested to run as unpriv user, ctl+c and restart with -u? press enter to continue without')

if not os.path.exists(UPLOAD_FOLDER): # create the folder to upload the files into if it does not exist
    os.mkdir(UPLOAD_FOLDER)
    if args.unprivileged:
        subprocess.call('chown ' + UNPRIV_USER + ':' + UNPRIV_USER + ' ' + UPLOAD_FOLDER, shell=True)
if not os.path.exists(LOG_FOLDER): # create the folder to hold logs and output materials if it also dne
    os.mkdir(LOG_FOLDER)
    if args.unprivileged:
        subprocess.call('chown ' + UNPRIV_USER + ':' + UNPRIV_USER + ' ' + LOG_FOLDER, shell=True)
if not os.path.exists(DATABASE): # set up the database in UPLOAD_FOLDER if it does not exist
    subprocess.call('touch ' + DATABASE, shell=True)
    if args.unprivileged:
        subprocess.call('chown ' + UNPRIV_USER + ':' + UNPRIV_USER + ' ' + DATABASE, shell=True)
