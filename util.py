from config import *
import hashlib

def md5(fname): ## opens a file and calculates the md5 (memory efficient, from https://stackoverflow.com/a/3431838)
	hash_md5 = hashlib.md5()
	with open(fname, "rb") as f:
		for chunk in iter(lambda: f.read(4096), b""): # read 4kb chunks and update the hashlib function
			hash_md5.update(chunk)
	return hash_md5.hexdigest()

def allowed_file(filename):
	for ext in ALLOWED_EXTENSIONS:
		if filename.endswith(ext): # checks the filename against all the allowed extensions (pcap, pcapng in this case)
			return True
	return False

if not os.path.exists(UPLOAD_FOLDER): # create the folder to upload the files into if it does not exist
	os.mkdir(UPLOAD_FOLDER)
if not os.path.exists(LOG_FOLDER): # create the folder to hold logs and output materials if it also dne
	os.mkdir(LOG_FOLDER)
if not os.path.exists(DATABASE): # set up the database if it does not exist
	db = sqlite3.connect(DATABASE)
	c = db.cursor()
	c.execute('CREATE TABLE pcaps (name text, file text, status boolean, logpath text, md5 text, uploaded int)')
	db.commit()
	db.close()
