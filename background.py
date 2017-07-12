from config import *
import threading, os, time ### TODO: time the operation and save in db
from peewee import *

db = SqliteDatabase(DATABASE)

threadlock = threading.Lock()
datalock = threading.Lock()

def backgroundthread(run): # runs in the background and processes files one at a time
	global threadlock,datalock
	try:
		print 'background thread picked up {} with {}, processing now...'.format(run.pcap.filename,run.ids) # debug statement
		logpath = os.path.join(LOG_FOLDER,run.ids+'-'+run.pcap.filename) # make a folder in the log directory that is tagged with the engine and file name
		os.mkdir(logpath)
		os.chdir(IDSDB_FOLDER) # cd to the path of the IDSDeathBlossom install so all the relative links and imports work properly
		threadlock.acquire(True) # make sure we don't run these at the same time
		ret = os.system('''python {IDSDB}/IDSDeathBlossom.py -c {IDSDB}/config/config.yaml -R run -t "{IDS}-{ENGINE}" --pcappath="{PCAP}" --globallogdir={LOGPATH} --glogoverride --reporton=ids,fast'''.format(IDSDB=IDSDB_FOLDER,IDS=run.ids,ENGINE=run.engine,PCAP=run.pcap.filepath,LOGPATH=logpath))  ## --use-custom-rules  --target-opts="all:customrules='.$rulesfile.'"
		threadlock.release()
		stat = 1 # success
		if ret != 0:
			stat = -1 # fail
		files = os.listdir(logpath) # see what files were created
		print files # for debugging
		datalock.acquire()
		try:
			db.connect()
		except:
			pass
		run.logpath = logpath
		run.status = stat
		run.save()
		db.close()
		datalock.release()
	except Exception as e:
		print e

def process(info): # start the thread, passing the file info to it
	bthread = threading.Thread(target=backgroundthread,args=(info,))
	bthread.start()
