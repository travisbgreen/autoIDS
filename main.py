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
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER ## we want to save all the pcaps so this is not a tmp folder in the default config
app.secret_key = SECRETKEY ## be sure to change this in the config so you can't be pwn3d by 1337 h4x0rz

filequeue = Queue.Queue() # processing queue for the files that are uploaded
background.start(filequeue) # this starts a thread that blocks until a file is in the queue

@app.route('/') # main page = upload spot
def mainpage():
	return render_template('upload.html',engines=ENGINES) # list of the engines available goes into the dropdown in the form

@app.route('/upload',methods=['POST']) # post to this actually triggers upload (so it could be done with cURL if you want)
def upload():
	global filequeue # so we can access this
	print request.files # debug statement showing what they are trying to upload
	if not 'file' in request.files: # if there's no file included, try again
		flash('no file in form') # this displays a message at tnbe top of the next page they load, in this case, the main page
		return redirect('/')
	file = request.files['file'] # just one file that we're uploading
	if file.filename == '': # invalid filename also means not selected in the form
		flash('no selected file')
		return redirect('/')
	if file and allowed_file(file.filename): # check if the filename ends with .pcap or .pcapng (can be changed in config)
		filename = time.strftime('%m%d%Y.%H%M-') + secure_filename(file.filename) # prepend a date and time stamp
		origfilename = secure_filename(file.filename) # keep this around as well to put into the db later
		engine = request.form.get('engine','suricata-2.0.6') # gets the selected engine from the dropdown in the form, defaulting to suri 206
		path = os.path.join(app.config['UPLOAD_FOLDER'], filename) # keep the full path to the uploaded file
		print 'saving file...',filename # another debug statement
		file.save(path) # saves to the permentant storage dir
		filehash = md5(path) # hash the file so we can see if it was already uploaded
		#### TODO: maybe acquire a lock so that other threads will not interfere with the DB while we write to it
		db = sqlite3.connect(DATABASE) # connect to the SQLite db to store the file info
		c = db.cursor()
		c.execute('SELECT * FROM pcaps WHERE md5=?',(filehash,)) # check if there is alredy a pcap in the database that has the md5 of this one
		existing = c.fetchone()
		if existing: # if there is not an empty array
			flash('that file hash is already in the database!')
			return redirect('/output/'+filehash) # redirect to the page for the existing file
		c.execute('INSERT INTO pcaps VALUES (?,?,?,?,?,?)',(origfilename,filename,0,'',filehash,time.time())) # otherwise store the new pcap data into the database
		db.commit() # save the db
		db.close()
		filequeue.put((filename,engine,filehash,path)) # add the info for the new file to the processing queue
		flash('processing pcap in progress... wait a little while and then refresh') # give the user a message about the status
		return redirect('/output/'+filehash) # redirect to the page for the unfinished sample

@app.route('/output') # displays a list of the pcaps submitted to the system
def logfilelist():
	page = int(request.args.get('page',1)) # can use ?page=2 or something to paginate the system (rudimentary navigation on the page already)
	db = sqlite3.connect(DATABASE) # get the database
	c = db.cursor()
	c.execute('SELECT * FROM pcaps ORDER BY uploaded DESC LIMIT ? OFFSET ?',(40,40*(page-1))) # get 40 pcaps, skipping 40*page offset
	files = c.fetchall() # get them all for display
	db.close()
	return render_template('listing.html',files=files,page=page) # pass in the page number and the file listing

@app.route('/output/<filehash>') # displays the logs of a single file
def logfiledisp(filehash):
	db = sqlite3.connect(DATABASE) # get the database
	c = db.cursor()
	c.execute('SELECT * FROM pcaps WHERE md5=?',(filehash,)) # find the pcap since we're identifying them by hash
	data = c.fetchone()
	if not data:
		flash('that file does not exist') # if there's no pcap with that hash, redirect to the listing
		return redirect('/output')
	### TODO: finish the processing that happens here
	db.close()
	files = []
	if data[3]:
		filenames = os.listdir(data[3])
		for fn in filenames:
			fd = open(os.path.join(data[3],fn),'r')
			files.append((fn,fd.read()))
			fd.close()
	return render_template('logfile.html',data=data,files=files) # pass in the logs

if __name__ == '__main__': # debugging mode - just run the py file
	#app.debug = True
	app.host = '0.0.0.0'
	app.port = 19943 # does not work in the new flask
	app.run()
	# after app.run finishes (ctrl-c), we then kill the background thread
	filequeue.put((-1,-1)) ## definitely not a filename, will cause the background thread to exit
