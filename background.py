from config import *
import threading, os, sqlite3, time ### TODO: time the operation and save in db

def backgroundthread(filequeue): # runs in the background and processes files one at a time
	while 1:
		try:
			filename,engine,filehash = filequeue.get(True) # blocks until someone submits a file
			if filename == -1: # value that is designed to make the thread exit
				return
			print 'background thread picked up {} with {}, processing now...'.format(filename,engine) # debug statement
			logpath = os.path.join(LOG_FOLDER,engine+'-'+filename) # make a folder in the log directory that is tagged with the engine and file name
			os.mkdir(logpath)
			os.chdir(IDSDB_FOLDER) # cd to the path of the IDSDeathBlossom install so all the relative links and imports work properly
			ret = os.system('''python {IDSDB}/IDSDeathBlossom.py -c {IDSDB}/config/config.yaml -R run -t "{ENGINE}-test-test" --pcappath="{PCAP}" --globallogdir={LOGPATH} --glogoverride --reporton=ids,fast'''.format(IDSDB=IDSDB_FOLDER,ENGINE=engine,PCAP=filename,LOGPATH=logpath))  ## --use-custom-rules  --target-opts="all:customrules='.$rulesfile.'"
			files = os.listdir(logpath) # see what files were created
			print files # for debigging
			db = sqlite3.connect(DATABASE) # connect to db to report results
			c = db.cursor()
			c.execute('UPDATE pcaps SET status=?,logpath=? WHERE md5=?',(True,logpath,filehash)) # update the db row of that file
			db.commit() # and save db
			db.close()
		except Exception as e: # want to make sure any error doesn't make this thread exit
			print e

def start(fq): # start the thread, passing the file queue to it
	bthread = threading.Thread(target=backgroundthread,args=(fq))
	bthread.start()
