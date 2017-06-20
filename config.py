import sqlite3,os

UPLOAD_FOLDER = '/var/pcap' # pcap files are uploaded here
LOG_FOLDER = '/var/pcap/logs' # logs are put here in their own folders
IDSDB_FOLDER = '/opt/IDSDeathBlossom' # IDSDeathBlossom installation
DATABASE = os.path.join(UPLOAD_FOLDER,'files.db') # path to the SQLite database that stores some info about files
ALLOWED_EXTENSIONS = set(['pcap','pcapng']) # allowed file types to upload
ENGINES = ['snort-2.8.4.1', 'snort-2.8.5.1', 'snort-2.8.6.1','snort-2.9.0.5', 'snort-2.9.6.2', 'suricata-1.2.1','suricata-1.3.6', 'suricata-1.4.7', 'suricata-2.0.6'] # engines that can be chosen on the upload page

SECRETKEY = 'jasfpqurvpwhgq9pw34rn3qy42996h7d6gf8h5j4kj5hg679s08df7g0d8fg6hd89sfg8767b8v69b87n6cvb87n6cvnd5987erytwejkrh252mbn52mb5l2l54j2l50nvu3w754yt237098572307509878twe0rt98we70rt89gf7hdfg7h089fgh7df098h' # for session cookie encryption
