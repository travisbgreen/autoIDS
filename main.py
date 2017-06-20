from flask import Flask, request, redirect, url_for, render_template, flash
from werkzeug.utils import secure_filename
import os
import Queue
import sqlite3
import time
from config import *
from util import *
import background

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = SECRETKEY

filequeue = Queue.Queue()
background.start(filequeue)

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
