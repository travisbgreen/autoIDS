from config import *
import hashlib

def md5(fname): ## https://stackoverflow.com/a/3431838
	hash_md5 = hashlib.md5()
	with open(fname, "rb") as f:
		for chunk in iter(lambda: f.read(4096), b""):
			hash_md5.update(chunk)
	return hash_md5.hexdigest()

def allowed_file(filename):
	return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

if not os.path.exists(UPLOAD_FOLDER):
	os.mkdir(UPLOAD_FOLDER)
if not os.path.exists(LOG_FOLDER):
	os.mkdir(LOG_FOLDER)
if not os.path.exists(DATABASE):
	db = sqlite3.connect(DATABASE)
	c = db.cursor()
	c.execute('CREATE TABLE pcaps (name text, file text, status boolean, logpath text, md5 text, uploaded int)')
	db.commit()
	db.close()
