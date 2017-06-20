import sqlite3,os

UPLOAD_FOLDER = '/var/pcap'
LOG_FOLDER = '/var/pcap/logs'
IDSDB_FOLDER = '/opt/IDSDeathBlossom'
DATABASE = os.path.join(UPLOAD_FOLDER,'files.db')
ALLOWED_EXTENSIONS = set(['pcap','pcapng'])
ENGINES = ['snort-2.8.4.1', 'snort-2.8.5.1', 'snort-2.8.6.1','snort-2.9.0.5', 'snort-2.9.6.2', 'suricata-1.2.1','suricata-1.3.6', 'suricata-1.4.7', 'suricata-2.0.6']

SECRETKEY = 'jasfpqurvpwhgq9pw34rn3qy42996h7d6gf8h5j4kj5hg679s08df7g0d8fg6hd89sfg8767b8v69b87n6cvb87n6cvnd5987erytwejkrh252mbn52mb5l2l54j2l50nvu3w754yt237098572307509878twe0rt98we70rt89gf7hdfg7h089fgh7df098h'
