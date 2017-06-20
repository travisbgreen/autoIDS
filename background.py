from config import *
import threading, os, sqlite3

def backgroundthread(filequeue):
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

def start(fq):
	bthread = threading.Thread(target=backgroundthread,args=(fq))
	bthread.start()
