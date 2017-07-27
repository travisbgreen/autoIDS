from config import *
import threading, os, time, sys, tempfile
from peewee import *

db = SqliteDatabase(DATABASE, threadlocals=True)

threadlock = threading.Lock() # make sure we don't have any threading issues
datalock = threading.Lock()

sys.path.append(IDSDB_FOLDER)
from IDSDeathBlossom import run as run_ids

def backgroundthread(run): # runs in the background and processes files one at a time
	try:
		print 'background thread picked up {} with {}, processing now...'.format(run.pcap.filename,run.ids) # debug statement
		logpath = os.path.join(LOG_FOLDER,run.pcap.md5+run.runid) # make a folder in the log directory that is tagged with a long hash
		os.mkdir(logpath) # make a new subdirectory for the logs of this run to be stored in
		os.chdir(IDSDB_FOLDER) # cd to the path of the IDSDeathBlossom install so all the relative links and imports work properly
		rulesfile = tempfile.NamedTemporaryFile(delete=True) # make a temporary file for the rules if it has them
		class temp_config: # passed to IDSDB handler
			runmode = 'run' # what else would you want to do?
			config = '{IDSDB}/config/config.yaml'.format(IDSDB=IDSDB_FOLDER) # default config
			targets = '{IDS}-{ENGINE}'.format(IDS=run.ids,ENGINE=run.engine) # set the ids and ruleset
			pcappath = run.pcap.filepath # path to the pcap to be executed
			globallogdir = logpath # point to our special logging path
			glogoverride = True # i guess this means send all logs to that folder
			reporton = 'ids,fast' # things to report about
		if run.engine == 'test-test': # custom rules
			rulesfile.write(run.rules) # write the rules to our temp file
			rulesfile.flush() # save without closing because that deletes the file
			temp_config.usecustomrules = True # tell it to use our rules
			temp_config.target-opts = 'all:customrules="{RULEFILE}"'.format(rulesfile.name) # point it at our file
		starttime = time.clock()
		with threadlock:
			ret = run_ids(temp_config) # runs the program directly without bash
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
