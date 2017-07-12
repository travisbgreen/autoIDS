#!/usr/bin/env python2
from flask import Flask, request, redirect, url_for, render_template, flash
from werkzeug.utils import secure_filename
import os
import Queue
from peewee import *
import time
from config import *
from util import *
from background import process,datalock
from pygments import highlight
from pygments.lexers import guess_lexer, get_lexer_by_name
from pygments.formatters import HtmlFormatter

### database stuff here for now.
db = SqliteDatabase(DATABASE, threadlocals=True)

class Pcap(Model):
	md5 = CharField()
	filename = CharField()
	filepath = CharField()
	uploaded = IntegerField()  # unixtime
	private = BooleanField()
	class Meta:
		database = db

class ProcessedPcap(Model):
	runid = CharField()
	engine = CharField()
	ids = CharField()
	rules = TextField()
	status = IntegerField()
	logpath = CharField()
	run = IntegerField()     # also unixtime
	pcap = ForeignKeyField(Pcap, related_name='runs')
	class Meta:
		database = db

db.connect()
try:
	db.create_tables([Pcap,ProcessedPcap])
except OperationalError:
	pass # tables aready exist
db.close()

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER ## we want to save all the pcaps so this is not a tmp folder in the default config
app.secret_key = SECRETKEY ## be sure to change this in the config so you can't be pwn3d by 1337 h4x0rz

@app.route('/') # main page = upload spot
def mainpage():
	return render_template('upload.html',idss=IDSS,rerun=False) # list of the engines available goes into the dropdown in the form

@app.route('/rerun/<filehash>')
def rerun(filehash):
	try:
		reruninfo = Pcap.select().where(Pcap.md5==filehash).get()
	except:
		flash('that file does not exist so it can not be rerun')
		return redirect('/')
	return render_template('upload.html',idss=IDSS,rerun=True,rerunhash=filehash)

@app.route('/upload',methods=['POST']) # post to this actually triggers upload (so it could be done with cURL if you want)
def upload():
	global datalock
	try:
		db.connect()
	except:
		pass

	allowed = False
	reupload = False
	if request.files:
		if not 'file' in request.files: # if there's no file included, try again
			flash('no file in form') # this displays a message at the top of the next page they load, in this case, the main page
			return redirect('/')
		file = request.files['file'] # just one file that we're uploading
		if file.filename == '': # invalid filename also means not selected in the form
			flash('no selected file')
			return redirect('/')
		if file and allowed_file(file.filename): # check if the filename ends with .pcap or .pcapng (can be changed in config)
			savefilename = time.strftime('%m%d%Y.%H%M-') + secure_filename(file.filename) # prepend a date and time stamp
			filename = file.filename
			path = os.path.join(app.config['UPLOAD_FOLDER'], savefilename) # keep the full path to the uploaded file
			file.save(path) # saves to the permentant storage dir
			filehash = md5(path) # hash the file so we can see if it was already uploaded
			allowed = True
	elif 'rerunhash' in request.form:
		try:
			filehash = request.form.get('rerunhash')
			print filehash
			reruninfo = Pcap.select().where(Pcap.md5==filehash).get()
			filename = reruninfo.filename
			path = reruninfo.filepath
			allowed = True
			reupload = True
		except:
			allowed = False
	if not allowed:
		flash('unhelpful error message')
		return redirect('/')

	ids = request.form.get('ids','suricata-2.0.6') # gets the selected engine from the dropdown in the form, defaulting to suri 206
	private = request.form.get('private',False) # checkbox that makes the file private
	engine = request.form.get('engine','etopen-all')
	rules = request.form.get('rules','')
	datalock.acquire()
	runid = hashlib.md5(ids+engine+rules).hexdigest()
	try:
		pcap = Pcap.select().where(Pcap.md5==filehash).get()
	except:
		pass #flash('that file hash is already in the database!')
	try:
		query = ProcessedPcap.select(ProcessedPcap,Pcap).join(Pcap).where(ProcessedPcap.pcap.md5==filehash, ProcessedPcap.runid==runid)
		flash('that file has already been processed with those settings!')
		return redirect('/output/'+filehash+'/'+runid)
	except:
		pass
	if not reupload:
		pcap = Pcap.create(md5=filehash,filename=filename,filepath=path,uploaded=time.time(),private=private)
	run = ProcessedPcap.create(runid=runid,pcap=pcap,ids=ids,engine=engine,rules=rules,status=0,logpath='',run=time.time())
	db.close()
	datalock.release()
	process(run) # opens a new thread to process the pcap
	flash('processing pcap in progress... wait a little while and then refresh') # give the user a message about the status
	if private:
		flash('this is a private pcap - if you lose the URL, you won\'t be able to find it again') # warn user when creating a private upload
	return redirect('/output/'+filehash+'/'+runid) # redirect to the page for the unfinished sample

@app.route('/output') # displays a list of the pcaps submitted to the system
def logfilelist():
	page = int(request.args.get('page',1)) # can use ?page=2 or something to paginate the system (rudimentary navigation on the page already)
	try:
		db.connect()
	except:
		pass
	try:
		files = ProcessedPcap.select(ProcessedPcap,Pcap).join(Pcap).where(Pcap.private==False).order_by(ProcessedPcap.run.desc()).paginate(page,PERPAGE)
	except:
		files = []
	nextpage = len(files) >= PERPAGE
	db.close()
	return render_template('listing.html',files=files,page=page,nextpage=nextpage) # pass in the page number and the file listing

@app.route('/output/<filehash>')
def logfileselect(filehash): # lists all the logfiles associated with a specific pcap
	page = int(request.args.get('page',1)) # can use ?page=2 or something to paginate the system (rudimentary navigation on the page already)
	try:
		db.connect()
	except:
		pass
	try:
		ofile = Pcap.select().where(Pcap.md5==filehash).get()
	except:
		flash('that file does not exist') # if there's no pcap with that hash, redirect to the listing
		return redirect('/output')
	try:
		runs = ProcessedPcap.select(ProcessedPcap,Pcap).join(Pcap).where(Pcap.md5==filehash).order_by(ProcessedPcap.run.desc()).paginate(page,PERPAGE)
	except:
		runs = []
	nextpage = len(runs) >= PERPAGE
	db.close()
	return render_template('filehash.html',file=ofile,runs=runs,page=page,nextpage=nextpage)

@app.route('/output/<filehash>/<runid>') # displays the logs of a single file
def logfiledisp(filehash,runid):
	try:
		db.connect()
	except:
		pass # get the database
	try:
		data = ProcessedPcap.select(ProcessedPcap,Pcap).join(Pcap).where(Pcap.md5==filehash, ProcessedPcap.runid==runid).get()
	except:
		flash('that run or file does not exist') # if there's no pcap with that hash, redirect to the listing
		return redirect('/output')
	db.close()
	files = []
	if data.logpath:
		filenames = os.listdir(data.logpath)
		for fn in filenames:
			if fn in DISPLAYFILES or True: ## disable the 'or True' because its for debugging
				fd = open(os.path.join(data.logpath,fn),'r')
				raw = fd.read()
				fd.close()
				if not raw:
					continue
				if raw.startswith('{'):
					lexer = get_lexer_by_name('json')
				else:
					lexer = get_lexer_by_name('makefile')
				formatter = HtmlFormatter(linenos=True)
				formatted = highlight(raw,lexer,formatter)
				files.append((fn,formatted))
	css = HtmlFormatter().get_style_defs('.highlight')
	return render_template('logfile.html',css=css,data=data,files=files) # pass in the logs

if __name__ == '__main__': # debugging mode - just run the py file
	#app.debug = True
	app.host = '0.0.0.0'
	app.port = 19943 # does not work in the new flask
	app.run()
