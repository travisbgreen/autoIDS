from config import *
import threading, os, time ### TODO: time the operation and save in db
from peewee import *

db = SqliteDatabase(DATABASE, threadlocals=True)

threadlock = threading.Lock() # make sure we don't have any threading issues
datalock = threading.Lock()

def backgroundthread(run): # runs in the background and processes files one at a time
	global threadlock,datalock
	try:
		print 'background thread picked up {} with {}, processing now...'.format(run.pcap.filename,run.ids) # debug statement
		logpath = os.path.join(LOG_FOLDER,run.pcap.md5+run.runid) # make a folder in the log directory that is tagged with a long hash
		os.mkdir(logpath) # make a new subdirectory for the logs of this run to be stored in
		os.chdir(IDSDB_FOLDER) # cd to the path of the IDSDeathBlossom install so all the relative links and imports work properly
		threadlock.acquire(True) # make sure we don't run these at the same time
		starttime = time.clock()
		ret = os.system('''python {IDSDB}/IDSDeathBlossom.py -c {IDSDB}/config/config.yaml -R run -t "{IDS}-{ENGINE}" --pcappath="{PCAP}" --globallogdir={LOGPATH} --glogoverride --reporton=ids,fast'''.format(IDSDB=IDSDB_FOLDER,IDS=run.ids,ENGINE=run.engine,PCAP=run.pcap.filepath,LOGPATH=logpath))  ## --use-custom-rules  --target-opts="all:customrules='.$rulesfile.'"
		endtime = time.clock()
		threadlock.release() # this lock only prevents IDSdb from running multiple times at once
		stat = 1 # success
		if ret != 0:
			stat = -1 # fail
		files = os.listdir(logpath) # see what files were created
		print files # for debugging
		datalock.acquire() # different lock for database operations (shared with main.py)
		try:
			db.connect() # sometimes it will error if it is already connected
		except:
			pass
		run.logpath = logpath # set the newly created directory
		run.status = stat # and the status finalized
		run.runtime = endtime - starttime
		run.save() # save databse reference
		db.close()
		datalock.release() # allow other threads to write db
	except Exception as e: ##TODO: maybe set status to fail on error
		print e

def process(info): # start the thread, passing the file info to it
	bthread = threading.Thread(target=backgroundthread,args=(info,)) # pass in database reference
	bthread.start()
