from config import *
import subprocess, threading, os, time, sys, tempfile
from peewee import *

db = SqliteDatabase(DATABASE, threadlocals=True)

threadlock = threading.Lock() # make sure we don't have any threading issues
datalock = threading.Lock()

def backgroundthread(run): # runs in the background and processes files one at a time
	try:
		print 'background thread picked up {} with {}, processing now...'.format(run.pcap.filename,run.ids) # debug statement
		logpath = os.path.join(LOG_FOLDER,run.pcap.md5+run.runid) # make a folder in the log directory that is tagged with a long hash
		os.mkdir(logpath) # make a new subdirectory for the logs of this run to be stored in
		os.chdir(IDSDB_FOLDER) # cd to the path of the IDSDeathBlossom install so all the relative links and imports work properly
		rulesfile = tempfile.NamedTemporaryFile(delete=True) # make a temporary file for the rules if it has them
		opts = ["python", "{IDSDB}/IDSDeathBlossom.py".format(IDSDB=IDSDB_FOLDER),
		   "-c", "{IDSDB}/config/config.yaml".format(IDSDB=IDSDB_FOLDER), "-R", "run",
		   "-t", "'{IDS}-{ENGINE}'".format(IDS=run.ids,ENGINE=run.engine),
		   "--pcappath='{PCAP}'".format(PCAP=run.pcap.filepath), "--globallogdir={LOGPATH}".format(LOGPATH=logpath),
		   "--glogoverride", "--reporton=ids,fast"]
		if run.engine == 'test-test': # custom rules
			rulesfile.write(run.rules) # write the rules to our temp file
			rulesfile.flush() # save without closing because that deletes the file
			opts += ["--use-custom-rules",  "--target-opts='all:customrules=\"{RULEFILE}\"'".format(RULEFILE=rulesfile.name)]
		starttime = time.clock()
		with threadlock:
			ret = subprocess.call(opts) # doesn't use a shell apparently
		endtime = time.clock()
		rulesfile.close() # delete the temp file
		stat = 1 # success
		if ret != 0:
			stat = -1 # fail
		with datalock:
			with db.transaction():
				run.logpath = logpath # set the newly created directory
				run.status = stat # and the status finalized
				run.runtime = endtime - starttime
	except Exception as e:
		with datalock:
			with db.transaction():
				run.status = -1 # errored

def process(info): # start the thread, passing the file info to it
	bthread = threading.Thread(target=backgroundthread,args=(info,)) # pass in database reference
	bthread.start()
