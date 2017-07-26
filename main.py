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
db = SqliteDatabase(DATABASE, threadlocals=True) # peewee reference to the database

class Pcap(Model): # store info about a specific pcap
	md5 = CharField() # file hash
	filename = CharField() # original filename
	filepath = CharField() # path to the uploaded file
	uploaded = IntegerField() # unixtime for when it was uploaded
	private = BooleanField() # if the uploader wanted it to be private
	class Meta:
		database = db # connect it to the database

class ProcessedPcap(Model): # store info about logs of a specific run of a pcap
	runid = CharField() # hash identifier for the specific settings for that run
	engine = CharField() # the ruleset that is used (like etopen-all)
	ids = CharField() # ids that is used (like suricata-2.0.6)
	rules = TextField() # custom rules that are specified
	status = IntegerField() # in progress, success, failed
	logpath = CharField() # path to the resulting log files
	run = IntegerField() # unixtime for when it was run
	pcap = ForeignKeyField(Pcap, related_name='runs') # relate it to the pcap that it describes
	class Meta:
		database = db # connect it to the database

db.connect()
try:
	db.create_tables([Pcap,ProcessedPcap]) # make the tables that we just described
except OperationalError: # if tables already exist, this will error
	pass # just continue
db.close()

app = Flask(__name__) # make the flask
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER ## we want to save all the pcaps so this is not a tmp folder in the default config
app.secret_key = SECRETKEY ## be sure to change this in the config so you can't be pwn3d by 1337 h4x0rz

@app.route('/') # main page = upload spot
def mainpage():
	return render_template('upload.html',idss=IDSS,engines=ENGINES,rerun=False) # list of the engines and idss available goes into the dropdown in the form

@app.route('/rerun/<filehash>') # page to re-run a file without reuploading it
def rerun(filehash):
	try:
		reruninfo = Pcap.select().where(Pcap.md5==filehash).get() # make sure the file exists
	except:
		flash('that file does not exist so it can not be rerun') # if it does not...
		return redirect('/')
	return render_template('upload.html',idss=IDSS,engines=ENGINES,rerun=True,rerunhash=filehash) # tell the main page that this is a re-run file

@app.route('/upload',methods=['POST']) # post to this actually triggers upload (so it could be done with cURL if you want)
def upload():
	global datalock # for exclusive access to the database
	try:
		db.connect()
	except: # might error if it was not closed properly
		pass

	allowed = False # series of checks determine if the upload is allowed
	reupload = False # more checks determine if the file has already been uploaded
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
			filename = file.filename # save this so we can put it into the database
			path = os.path.join(app.config['UPLOAD_FOLDER'], savefilename) # keep the full path to the uploaded file
			file.save(path) # saves to the permentant storage dir
			filehash = md5(path) # hash the file so we can see if it was already uploaded
			allowed = True # allowed to proceed
	elif 'rerunhash' in request.form: # not a file upload, but a re-run via file hash
		try:
			filehash = request.form.get('rerunhash') # get the hash from the form
			print filehash # for debugging
			reruninfo = Pcap.select().where(Pcap.md5==filehash).get() # check if the file exists
			filename = reruninfo.filename # get the info from the database
			path = reruninfo.filepath
			allowed = True # allowed to proceed
			reupload = True
		except:
			allowed = False # the database likely errored if the hash did not exist
	if not allowed:
		flash('unhelpful error message') # because there are several reasons the upload would be denied, not very helpful
		return redirect('/')

	ids = request.form.get('ids','suricata-2.0.6') # gets the selected engine from the dropdown in the form, defaulting to suri 206
	private = request.form.get('private',False) # checkbox that makes the file private
	engine = request.form.get('engine','etopen-all') # ruleset selection
	rules = request.form.get('rules','') # textbox that carries custom rules
	datalock.acquire() # we're writing to the db so we need to get exclusive access
	runid = hashlib.md5(ids+engine+rules).hexdigest() # make a run id that identifies the different runs that each file may have
	try:
		pcap = Pcap.select().where(Pcap.md5==filehash).get() # check to see if there is any pcap with the same hash as the one that was uploaded
		if pcap and not reupload: # if there is, but it's not marked as a reupload,
			os.remove(path) # delete the new one because it's a duplicate
			reupload = True # this is marked as a reupload so we don't put an extra entty into the pcap database
	except: # the select will fail if no file exists
		pass
	try:
		query = ProcessedPcap.select(ProcessedPcap,Pcap).join(Pcap).where(ProcessedPcap.pcap.md5==filehash, ProcessedPcap.runid==runid).get() # find if there is a run with the same pcap and settings
		flash('that file has already been processed with those settings!') # don't run the same file again
		return redirect('/output/'+filehash+'/'+runid) # send the user to the page where the results are for that run
	except: # if the query fails, ignore
		pass
	if not reupload: # make a new entry in the pcap database if it's a new file (pcap is set before if it is a reupload/rerun)
		pcap = Pcap.create(md5=filehash,filename=filename,filepath=path,uploaded=time.time(),private=private) # create entry
	run = ProcessedPcap.create(runid=runid,pcap=pcap,ids=ids,engine=engine,rules=rules,status=0,logpath='',run=time.time()) # create a run entry in the database
	db.close()
	datalock.release() # release exclusive lock
	process(run) # opens a new thread to process the pcap
	flash('processing pcap in progress... wait a little while and then refresh') # give the user a message about the status
	if private:
		flash('this is a private pcap - if you lose the URL, you won\'t be able to find it again') # warn user when creating a private upload
	return redirect('/output/'+filehash+'/'+runid) # redirect to the page for the unfinished sample

@app.route('/output') # displays a list of the pcaps submitted to the system
def logfilelist():
	page = int(request.args.get('page',1)) # can use ?page=2 or something to paginate the system (rudimentary navigation on the page already)
	try:
		db.connect() # could error if already connected
	except:
		pass
	try:
		files = ProcessedPcap.select(ProcessedPcap,Pcap).join(Pcap).where(Pcap.private==False).order_by(ProcessedPcap.run.desc()).paginate(page,PERPAGE) # get the most recent 40 runs that are public
	except:
		files = [] # if the query finds no files, it can error
	nextpage = len(files) >= PERPAGE # if the list is the same length as the page size, could mean that there is another page (not the best way to do this i'm sure)
	db.close()
	return render_template('listing.html',files=files,page=page,nextpage=nextpage) # pass in the page number and the file listing

@app.route('/output/<filehash>')
def logfileselect(filehash): # lists all the logfiles associated with a specific pcap
	page = int(request.args.get('page',1)) # can use ?page=2 or something to paginate the system (rudimentary navigation on the page already)
	try:
		db.connect() # could error if already connected
	except:
		pass
	try:
		ofile = Pcap.select().where(Pcap.md5==filehash).get() # get info about the original file to display at the top of the page
	except:
		flash('that file does not exist') # if there's no pcap with that hash, redirect to the listing
		return redirect('/output')
	try:
		runs = ProcessedPcap.select(ProcessedPcap,Pcap).join(Pcap).where(Pcap.md5==filehash).order_by(ProcessedPcap.run.desc()).paginate(page,PERPAGE) # get all the runs with a specific pcap file hash
	except:
		runs = [] # if error, empty listing
	nextpage = len(runs) >= PERPAGE # same pagination detection
	db.close()
	return render_template('filehash.html',file=ofile,runs=runs,page=page,nextpage=nextpage) # pass file info and page info

@app.route('/output/<filehash>/<runid>') # displays the logs of a single file
def logfiledisp(filehash,runid):
	try:
		db.connect() # could error if already connected
	except:
		pass # get the database
	try:
		data = ProcessedPcap.select(ProcessedPcap,Pcap).join(Pcap).where(Pcap.md5==filehash, ProcessedPcap.runid==runid).get() # get info for a specific run
	except:
		flash('that run or file does not exist') # if there's no pcap with that hash, redirect to the listing
		return redirect('/output')
	db.close() # no longer needed
	files = [] # list that holds file info that is passed to the page template
	if data.logpath: # if the file is in progress, there will not be any log path stored
		filenames = os.listdir(data.logpath) # get the filenames that are in the logpath
		for fn in filenames:
			if not fn in FILEBLACKLIST: # only format it if not blacklisted
				fdir = os.path.join(data.logpath,fn) # join full path
				fsize = os.path.getsize(fdir) # get the full size so that the user can see if it was truncated
				fd = open(fdir,'r') # open file
				raw = fd.read(FILETRUNCATE) # only read up to 16kb of the file
				fd.close()
				dllink = STATICHOST + data.pcap.md5 + data.runid + '/' + fn # make a download link for the static apache server
				trunc = fsize >= FILETRUNCATE # boolean indicating truncation
				if not raw: # don't display empty files
					continue
				if raw.startswith('{'): # guess json files
					lexer = get_lexer_by_name('json')
				else:
					lexer = get_lexer_by_name('makefile') # otherwise, use something that looks ok on TSV and other random stuff
				formatter = HtmlFormatter(linenos=True) # format to html
				formatted = highlight(raw,lexer,formatter) # run the syntax highlighing
				files.append((fn,formatted,trunc,fsize,dllink)) # append info to list
	css = HtmlFormatter().get_style_defs('.highlight') # get the css to pass in (could probably make this a bit better by putting it in a static file)
	return render_template('logfile.html',css=css,data=data,files=files) # pass in the log list

if __name__ == '__main__': # debugging mode - just run the py file
	#app.debug = True
	app.host = '0.0.0.0'
	app.port = 19943 # does not work in the new flask
	app.run()
