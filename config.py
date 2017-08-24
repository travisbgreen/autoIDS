import os

UNPRIV_USER = 'autoids' # username and password for the unprivelaged user that this is run as
UNPRIV_PASS = '495f4bf2d84e6db716a923f209bed881'

UPLOAD_FOLDER = '/var/pcap' # pcap files are uploaded here
LOG_FOLDER = '/var/www/html' # logs are put here in their own folders
IDSDB_FOLDER = '/opt/IDSDeathBlossom' # IDSDeathBlossom installation
DATABASE = os.path.join(UPLOAD_FOLDER,'files.db') # path to the SQLite database that stores some info about files
ALLOWED_EXTENSIONS = set(['pcap','pcapng']) # allowed file types to upload
IDSS = ["snort-2.8.4.1","snort-2.8.5.1","snort-2.8.6.1","snort-2.9.0.5","snort-2.9.2.3","snort-2.9.3.1","snort-2.9.4.6","snort-2.9.5.6","snort-2.9.6.0","snort-2.9.6.1","snort-2.9.6.2","snort-2.9.7.0","snort-2.9.7.2","snort-2.9.7.3","snort-2.9.7.5","snort-2.9.7.6","snort-2.9.8.0","snort-2.9.8.2","snort-2.9.8.3","snort-2.9.9.0","suricata-1.2.1","suricata-1.3.1","suricata-1.3.6","suricata-1.4.6","suricata-1.4.7","suricata-2.0","suricata-2.0.1","suricata-2.0.10","suricata-2.0.11","suricata-2.0.2","suricata-2.0.3","suricata-2.0.4","suricata-2.0.5","suricata-2.0.6","suricata-2.0.7","suricata-2.0.8","suricata-2.0.9","suricata-3.0","suricata-3.0.1","suricata-3.1","suricata-3.1.1","suricata-3.2","suricata-3.2.1","suricata-3.2.2","suricata-3.2.3","suricata-4.0.0"] # IDS that can be chosen on the upload page
ENGINES = ['etopen-all','etopen-base','etopenenall-all','etopenenall-base','etpro-all','etpro-base','etproenall-all','etproenall-all','sanitize-sopen','sanitize-spro','test-test'] # rulesets for each IDS
PERPAGE = 40 # files displayed per page for the lists
FILEBLACKLIST = ['IDSDeathBlossom.py.log_'] # filenames that are not displayed by the logfile viewer
FILETRUNCATE = 16384  # truncate after first 16kb of long files
STATICHOST = 'http://autoids.net:81/' # url to the apache server that hosts the logfiles

SECRETKEY = 'jasfpqurvpwhgq9pw34rn3qy42996h7d6gf8h5j4kj5zhg679s08df7g0d8fg6hd89sfg8767b8v69b87n6cvb87n6cvnd5987erytwejkrh252mbn52mb5l2l54j2l50nvu3w754yt237098572307509878twe0rt98we70rt89gf7hdfg7h089fgh7df098h' # for session cookie encryption
