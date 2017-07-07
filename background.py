from config import *
import threading, os, sqlite3, time ### TODO: time the operation and save in db

threadlock = threading.Lock()
datalock = threading.Lock()

def backgroundthread(info): # runs in the background and processes files one at a time
	global threadlock,datalock
	try:
		filename,engine,filehash,filepath = info
		print 'background thread picked up {} with {}, processing now...'.format(filename,engine) # debug statement
		logpath = os.path.join(LOG_FOLDER,engine+'-'+filename) # make a folder in the log directory that is tagged with the engine and file name
		os.mkdir(logpath)
		os.chdir(IDSDB_FOLDER) # cd to the path of the IDSDeathBlossom install so all the relative links and imports work properly
		threadlock.acquire(True)
		ret = os.system('''python {IDSDB}/IDSDeathBlossom.py -c {IDSDB}/config/config.yaml -R run -t "{ENGINE}-etopen-all" --pcappath="{PCAP}" --globallogdir={LOGPATH} --glogoverride --reporton=ids,fast'''.format(IDSDB=IDSDB_FOLDER,ENGINE=engine,PCAP=filepath,LOGPATH=logpath))  ## --use-custom-rules  --target-opts="all:customrules='.$rulesfile.'"
		threadlock.release()
		stat = 1 # success
		if ret != 0:
			stat = -1 # fail
		files = os.listdir(logpath) # see what files were created
		print files # for debugging
		datalock.acquire()
		db = sqlite3.connect(DATABASE) # connect to db to report results
		c = db.cursor()
		c.execute('UPDATE pcaps SET status=?,logpath=? WHERE md5=?',(stat,logpath,filehash)) # update the db row of that file
		db.commit() # and save db
		db.close()
		datalock.release()
	except Exception as e: 
		print e

def process(info): # start the thread, passing the file info to it
	bthread = threading.Thread(target=backgroundthread,args=(info,))
	bthread.start()
