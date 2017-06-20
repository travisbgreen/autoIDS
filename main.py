from flask import Flask, request, redirect, url_for, render_template, flash
from werkzeug.utils import secure_filename
import os
import threading
import Queue
import sqlite3
import time
import hashlib

UPLOAD_FOLDER = '/var/pcap'
LOG_FOLDER = '/var/pcap/logs'
IDSDB_FOLDER = '/opt/IDSDeathBlossom'
DATABASE = os.path.join(UPLOAD_FOLDER,'files.db')
ALLOWED_EXTENSIONS = set(['pcap','pcapng'])
ENGINES = ['snort-2.8.4.1', 'snort-2.8.5.1', 'snort-2.8.6.1','snort-2.9.0.5', 'snort-2.9.6.2', 'suricata-1.2.1','suricata-1.3.6', 'suricata-1.4.7', 'suricata-2.0.6']

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

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = 'jasfpqurvpwhgq9pw34rn3qy42996h7d6gf8h5j4kj5hg679s08df7g0d8fg6hd89sfg8767b8v69b87n6cvb87n6cvnd5987erytwejkrh252mbn52mb5l2l54j2l50nvu3w754yt237098572307509878twe0rt98we70rt89gf7hdfg7h089fgh7df098h'

filequeue = Queue.Queue()

def backgroundthread():
	global filequeue
	while 1:
		try:
			filename,engine,filehash = filequeue.get(True)
			if filename == -1:
				return
			print 'background thread picked up {} with {}, processing now...'.format(filename,engine)
			logpath = os.path.join(LOG_FOLDER,engine+'-'+filename)
			os.mkdir(logpath)
			os.chdir(IDSDB_FOLDER)
			ret = os.system('''python {IDSDB}/IDSDeathBlossom.py -c {IDSDB}/config/config.yaml -R run -t "{ENGINE}-test-test" --pcappath="{PCAP}" --globallogdir={LOGPATH} --glogoverride --reporton=ids,fast'''.format(IDSDB=IDSDB_FOLDER,ENGINE=engine,PCAP=filename,LOGPATH=logpath))  ## --use-custom-rules  --target-opts="all:customrules='.$rulesfile.'"
			files = os.listdir(logpath)
			print files
			db = sqlite3.connect(DATABASE)
			c = db.cursor()
			c.execute('UPDATE pcaps SET status=?,logpath=? WHERE md5=?',(True,logpath,filehash))
			db.commit()
			db.close()
		except Exception as e:
			print e

bthread = threading.Thread(target=backgroundthread)
bthread.start()

def md5(fname): ## https://stackoverflow.com/a/3431838
	hash_md5 = hashlib.md5()
	with open(fname, "rb") as f:
		for chunk in iter(lambda: f.read(4096), b""):
			hash_md5.update(chunk)
	return hash_md5.hexdigest()

def allowed_file(filename):
	return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def mainpage():
	return render_template('upload.html',engines=ENGINES)

@app.route('/upload',methods=['POST'])
def upload():
	global filequeue
	print request.files
	if not 'file' in request.files:
		flash('no file in form')
		return redirect('/')
	file = request.files['file']
	if file.filename == '':
		flash('no selected file')
		return redirect('/')
	if file and allowed_file(file.filename):
		filename = time.strftime('%m%d%Y.%H%M-') + secure_filename(file.filename)
		origfilename = secure_filename(file.filename)
		engine = request.form.get('engine','suricata-2.0.6')
		path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
		print 'saving file...',filename
		file.save(path)
		filehash = md5(path)
		db = sqlite3.connect(DATABASE)
		c = db.cursor()
		c.execute('SELECT * FROM pcaps WHERE md5=?',(filehash,))
		existing = c.fetchone()
		if existing:
			flash('that file hash is already in the database!')
			return redirect('/output/'+filehash)
		c.execute('INSERT INTO pcaps VALUES (?,?,?,?,?,?)',(origfilename,filename,False,'',filehash,time.time()))
		db.commit()
		db.close()
		filequeue.put((filename,engine,filehash))
		flash('processing pcap in progress... wait a little while and then refresh')
		return redirect('/output/'+filehash)

@app.route('/output')
def logfilelist():
	page = request.args.get('page',1)
	db = sqlite3.connect(DATABASE)
	c = db.cursor()
	c.execute('SELECT * FROM pcaps ORDER BY uploaded DESC LIMIT ? OFFSET ?',(40,40*(page-1)))
	files = c.fetchall()
	db.close()
	return render_template('listing.html',files=files,page=page)

@app.route('/output/<filehash>')
def logfilelist(filehash):
	db = sqlite3.connect(DATABASE)
	c = db.cursor()
	c.execute('SELECT * FROM pcaps WHERE md5=?',(filehash))
	data = c.fetchone()
	if not data:
		flash('that file does not exist')
		return redirect('/output')
	## do stuff
	db.close()
	return render_template('logfile.html',stuff=things)

if __name__ == '__main__':
	#app.debug = True
	app.host = '0.0.0.0'
	app.port = 19943
	app.run()

	filequeue.put((-1,-1)) ## definitely not a filename, will cause the background thread to exit
