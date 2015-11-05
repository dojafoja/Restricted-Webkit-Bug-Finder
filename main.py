import os
import re
import sqlite3
import urllib2
import httplib
import psutil
import socket
import random
import struct
try:
    from BeautifulSoup import BeautifulSoup
except ImportError:
    from bs4 import BeautifulSoup   
import BaseHTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler
import threading
import socket
import commands
import shutil
import tempfile
import subprocess
import time
import math
import datetime
import multiprocessing
# I was going to make this python2.7 and python3 compatible
# but I havent implemented it fully. I believe I would only need to
# implement urllib3 and fix imports. Also, the log parser needs to be 
# fixed to capture the urls properly as there are potentially 
# many bugs being missed out on.

# Python 3 imports
try:
    import tkinter as tk
    from tkinter import ttk
    from tkinter import messagebox as message
    from tkinter import filedialog
    from tkinter import scrolledtext as ScrolledText
# Python 2.7 imports
except ImportError:
    import Tkinter as tk
    import ttk
    import tkMessageBox as message
    import tkFileDialog as filedialog
    from ScrolledText import ScrolledText

db_name = 'commits.db'# Hardcoded database name
original_directory = os.getcwd()
if os.name == 'nt':
    dir_slash = "\\"
else:
    dir_slash = "/"
db_name = original_directory+dir_slash+db_name

#print(db_name)
class ServerThread (threading.Thread):
    finished = False
    def __init__(self, local_ip, path_to_host, layout_loc, file_path):
        threading.Thread.__init__(self)
        self.local_ip = local_ip
        self.layout_loc = layout_loc
        self.file_path=file_path       
        #self.host_path = path_to_host.rsplit(dir_slash,1)[0]
        self.host_file = path_to_host.rsplit(dir_slash,1)[1]
        print('path to host: ' + path_to_host)
    def run(self):        
        self.start_server()
       
    def start_server(self):
        try:
            os.chdir(self.layout_loc)
            #self.server_directory = os.getcwd()
            self.HandlerClass = SimpleHTTPRequestHandler
            self.ServerClass  = BaseHTTPServer.HTTPServer
            self.server = self.ServerClass((self.local_ip,8000), self.HandlerClass)
            self.serv_info = self.server.socket.getsockname()
            print "Serving "+self.host_file+" as index.html @ "+str(self.serv_info[0])+":"+str(self.serv_info[1]), "..."
            with open('index.html','w') as f:
                f.write('<script type="text/javascript">window.location.href="'+self.file_path+'"</script>')
            self.finished = True
            self.server.serve_forever() 
            return           
        except Exception as e:
            print(e)
            return
              
         
# The log parser
class LogParser():
    commit_list = []
    entry_count = 0
    #stop_date = 
    
    
    def __init__(self,log_file,stop_date):
        if os.path.isfile('commits.db'): 
            self.db_exists = True
            db = sqlite3.connect('commits.db')
            cursor = db.cursor()
            cursor.execute("SELECT revision FROM logs")
            results = cursor.fetchall()
            stop_rvn = max(results)[0] # Highest rvn in the database. When updating existing db, stop parsing when this is reached.
            db.close()
            print('Existing database was found and will be updated.')
        else:
            stop_rvn = None
            self.db_exists = False
            print('No database was found. A new one will be created.')
        bugs = ''
        rvn = ''
        url = []
        date = ''
            #stop_date = "2012-10-16"

                # the (?ims) is specifying flag optioons: ignore case, multiline (treat \n like characters), s (allows . to be extra greedy)
                # find bug that starts with r followed by any combination of numbers 0-9 that is 6 digits log followed by a space and a pipe
                # pipe is escaped to let python know we are looking for the character | since by default re treats it like a boolean or
                # This is followed by a wild card (.) and told to be greedy (gobble) until it hits a '-' that is repeated between 68-73 times.
                # Its actually 72 times but left some wiggle from for incorrect line terminators
                
        bugs = re.findall('(?ims)(^r[0-9]{5,7}.*?)-{68,73}', log_file.read())
        
        for bug in bugs:
                # find bug that starts with r followed by any combination of numbers 0-9 that is 6 digits log followed by a space and a pipe
                # pipe is escaped to let python know we are looking for the character | since by default re treats it like a boolean or
                # This is followed by a wild card (.) and told to be greedy (gobble) until up against another escaped |.
                # The next area is where the date/time is located so we wrap that up in paranthesis indicating its a subgroup of the whole
                # expression.  We grab the entire line and stop (? means less greedy) at the next |
                
            bugdate =  re.search('(?ims)r[0-9]{6} \|.*\|(.*?)\|', bug)
                
                #Next we check the match object to see if it contains something.  group(0) is the entire matched expression, group(1) is what is
                #contained with the paranthesis.  We split the string and grab the yyyy-mm-dd and check against the given date
                #if true it breaks out of the loop since we met our end date.
                
            if bugdate != None:
                date = bugdate.group(1).strip()
                if date.split(' ')[0] == stop_date:
                    break
            links = re.findall(r'(?ims)https://bugs.webkit.org/show_bug.cgi\?id\=[0-9]+', bug)
            if len(links) > 0:
                rvn = re.search('(r[0-9]{6}) \|', bug).group(1)
                if rvn == stop_rvn: 
                    break
                if links > 1:
                    for link in links:
                        self.commit_list.append((rvn,date,link.strip(),'\n'.join(bug.strip().split('\n')[1:])))
                        self.entry_count += 1
                else:
                    self.commit_list.append((rvn,date,links.strip(),'\n'.join(bug.strip().split('\n')[1:])))
                    self.entry_count += 1

        self.generate_db()

         
    def generate_db(self):
        self.number_errors = 0
        self.error_rvn = []
        db = sqlite3.connect(db_name)
        db.text_factory = str
        cursor = db.cursor()
        if self.db_exists == False:
            cursor.execute("CREATE TABLE logs(id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL, revision TEXT, date DATE,url TEXT, info TEXT, restricted INT, scanned INT)")
        for i in self.commit_list:
            try:            
                cursor.execute("INSERT INTO logs(revision,date, url, info) VALUES(?,?,?,?)", (i[0],i[1],i[2],i[3]))
            except Exception as e:
                self.number_errors += 1
                self.error_rvn.append(i[0])                
                print(e)
        print('Number of errors: ' + str(self.number_errors))
        print('Number of entries: ' + str(self.entry_count))
        for i in self.error_rvn:
            print(i)
            
        db.commit()
        db.close()      

hit = re.compile('\"bug_title\"\>Access Denied')


#########################################################################################
#Process Lock - Use this to lock a process so we can print without from other processes.#
#               For Debugging purposes only                                             #
#########################################################################################
#lock = multiprocessing.Lock()


def uget(url):
    start = time.time()
    page = urllib2.urlopen(url)
    html = page.read()
    if hit.search( html):
        return (url,1)
    else:
        return (url,0)

"""
spoofRSTattack is a function call to spawn multiple sockets that do nothing more than switch the
source IP/pair and Dest IP/pair and send a RST.  It results in killing the TIME_WAIT status
and frees up ports for more scans.  Vert hacky and violates the RFC for TIME_WAIT...love it
"""

def checksum(msg):          #calculates tcp checksum hdr so we send a valid packet 
	s = 0
	
	# loop taking 2 characters at a time
	for i in range(0, len(msg), 2):
		w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
		s = s + w
	s = (s>>16) + (s & 0xffff);
	s = s + (s >> 16);
	#complement and mask to 4 byte short
	s = ~s & 0xffff
	return s

def spoofRSTattack(ipconn):
    d_ip,d_p,s_ip,s_p = ipconn  #swapped our IP/Port pairs for spoofing
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    pid = multiprocessing.current_process().pid
    #Create IP Header fields for our raw socket, we are spoofing so we will swap our 
    ip_ver_ihl = (4 << 4) + 5
    ip_tos = 0
    ip_tot_len = 0
    ip_id = 31337
    ip_frag_off = 0
    ip_ttl = 64
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0
    ip_src_addr = socket.inet_aton(s_ip)
    ip_dst_addr = socket.inet_aton(d_ip)

    ip_hdr = struct.pack('!BBHHHBBH4s4s', ip_ver_ihl, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, \
                         ip_proto, ip_check, ip_src_addr, ip_dst_addr)
    #Create TCP Header field
    tcp_src_port = s_p
    tcp_dst_port = d_p
    tcp_seq = random.randrange(0xffffffff)
    tcp_ack = random.randrange(0xffffffff)
    tcp_data_off_res = 5 << 4
    tcp_flags = 4     #RST
    tcp_window = socket.htons(5840)
    chksum_pkt = struct.pack('!4s4sBBH', ip_src_addr, ip_dst_addr, 0,socket.IPPROTO_TCP,20)
    tcp_check = checksum(chksum_pkt)
    tcp_urg_ptr = 0

    tcp_hdr = struct.pack('!HHLLBBHHH', tcp_src_port, tcp_dst_port, tcp_seq, tcp_ack, tcp_data_off_res, \
                          tcp_flags,tcp_window,tcp_check, tcp_urg_ptr)
    rst_pkt = ip_hdr + tcp_hdr

    s.sendto(rst_pkt, ('127.0.0.1', 0))
    return pid
    
class HTMLScraper(BeautifulSoup,threading.Thread):
   
    def __init__(self,throttle_value):
        threading.Thread.__init__(self)
        BeautifulSoup.__init__(self)
        self.pid = 0
        self.connections = []
        self.denied_urls = []
        self.found_urls = []
        self.thread_count = throttle_value
        self.debug = False
        self.test_max = 645 # Used when self.debug = True
        self.abort = False
        
    def run(self):
        # Do a Query for all items where the restricted = 1 and where url scanned = 1
        # use last date for hard stop date.
        # Parse database, and determine last stopped...than start from there
        #
        db = sqlite3.connect(db_name)
        cursor = db.cursor()
   
        
        #################################################################################################
        #Starting point for scan. Determine how many have been scanned and than grab all unscanned urls.#
        #################################################################################################
        scanned = cursor.execute("SELECT COUNT(scanned) FROM logs WHERE scanned = 1").fetchone()[0]
        remaining = cursor.execute("SELECT COUNT(*) FROM logs WHERE scanned IS NULL").fetchone()[0]

        print "\nPreviosuly Scanned",scanned, "Remaining:", remaining

        url_count = remaining
        urls_checked = float(0)
        urls_found = float(0)
        
        cursor.execute("SELECT * FROM logs WHERE scanned IS NULL")
        results = cursor.fetchall()
     
        if self.debug == True:
            results = cursor.fetchall()[:self.test_max]
            url_count = self.test_max
            
        print "\nLoaded " +str(url_count) + " Bug Records"
        print "Beginning bug check...\nReports every " + str(self.thread_count*10) + " records"
        start_time = time.time()
        total_processed = 0

        pool = multiprocessing.Pool(processes = self.thread_count)
        error_range= []
        for i in range(0,url_count,self.thread_count):
            try:
                if self.abort == True:
                    raise Exception('UserAbortedScan')  # Dirty hack to stop scan if stop scan is clicked by the user.
                if (url_count - i) > self.thread_count: 
                    max_length = self.thread_count
                else:
                    max_length = url_count - i
                    
                urllist = [results[i+j][3] for j in range(max_length)]
                for us in pool.imap_unordered(uget, urllist):
                    if us != None:
                        u,s = us
                        if s == 1:
                            self.denied_urls.append(u)
                            print "\nFound: ", u
                        if s == 0:
                            self.found_urls.append(u)

                urls_checked += max_length

                #Begin RST Attack
                #   1.)  Get connections with fd -1, family 2, with a TIME_WAIT Status
                #   2.)  Create new list with the info and spawn a new pool of processes to spoof ourselves
                #   3.)  Clear chamber for next round of volleys
                #   4.)  Profit!
                try:
                    
                    for netconn in psutil.net_connections():
                        if netconn.fd == -1 and netconn.family == 2                 \
                        and netconn.status == "TIME_WAIT"                           \
                        and netconn.laddr[0] == "127.0.0.1"                         \
                        and netconn.raddr[0] == "127.0.0.1":
                            src_ip,src_port = netconn.laddr
                            dest_ip,dest_port = netconn.raddr
                            self.connections.append((src_ip,src_port,dest_ip,dest_port))
                            #spoofRSTattack((src_ip,src_port,dest_ip,dest_port))
                    for pid in  pool.imap_unordered(spoofRSTattack, self.connections):
                        if pid > 0:
                            pass
                except Exception as e:
                    print e.args
                self.connections = []
                                    
                
                #DO A BUNCH OF TIMING CALCULATIONS TO APPROXIMATE DURATION
                if urls_checked % (self.thread_count * 10) == 0:
                    stop_time = time.time()
                    total_time = float((stop_time - start_time )) / (self.thread_count * 10)   #gets average from 5 runs of # of threads
                    urls_remaining = url_count - urls_checked        #secs  #mins                        
                    time_remaining = round((((urls_remaining * total_time) / 60 )  /60),2)
                    time_remaining = str(time_remaining).split('.')
                    hours_remaining = time_remaining[0]
                    minutes_remaining = str((float(time_remaining[1])/100 * 60)).split('.')[0]  # uses percentage to approximate minutes remaining
                    if int(minutes_remaining) < 10:
                        minutes_remaining = '0'+minutes_remaining
                    percentage = round(float((urls_checked/url_count)) * 100,2)
                    total_time = 0
                    print "Found so far:", len(self.denied_urls)
                    print "\nURL's Remaining:", int(urls_remaining), "\tPercent Complete: ",  percentage
                    print "Approximate Time Remaining: " + hours_remaining +":"+minutes_remaining
                    start_time = time.time()

                if urls_checked == url_count:
                    print "\nPercent Complete: 100%"
            except Exception as e:
                    if str(e.args[0]).startswith("\'UnpickleableError"):
                        print "Throttling too High, terminating scan. Recommend not over 12 Processes\n"

                        print "Writing Results to the Database"
                        print "\nRestricted Found:", len(self.denied_urls), "Scanned:", len(self.found_urls) + len(self.denied_urls)
                        print "\nThis can take quite a while to complete. DO NOT CLOSE THE PROGRAM until\nthis finishes or SCAN results will not be saved. You will see a 'Done' message upon completion."
                        for url in self.denied_urls:
                            cursor.execute("UPDATE logs SET restricted = ?, scanned = ? WHERE url = ?",(1,1,url))
                        for url in self.found_urls:
                            cursor.execute("UPDATE logs SET restricted = ?, scanned = ? WHERE url = ?",(0,1,url))
                        print "Done...Exiting"
                        cursor.close()                        
                        db.commit()
                        db.close()
                        pool.terminate()
                        root.scan_running=False
                        #root.html_thread.clear()
                        self.clear()
                        return
                    elif str(e.args[0]) == 'UserAbortedScan':
                        print "User has aborted the scan...\n"

                        print "Writing Results to the Database"
                        print "\nRestricted Found:", len(self.denied_urls), "Scanned:", len(self.found_urls) + len(self.denied_urls)
                        print "\nThis can take quite a while to complete. DO NOT CLOSE THE PROGRAM until\nthis finishes or scan results will not saved. You will see a 'Done' message upon completion."
                        for url in self.denied_urls:
                            cursor.execute("UPDATE logs SET restricted = ?, scanned = ? WHERE url = ?",(1,1,url))
                        for url in self.found_urls:
                            cursor.execute("UPDATE logs SET restricted = ?, scanned = ? WHERE url = ?",(0,1,url))
                        print "Done...Exiting"
                        cursor.close()                        
                        db.commit()
                        db.close()
                        pool.terminate()
                        root.scan_running=False
                        #root.html_thread.clear()
                        self.clear()
                        return
                    else:
                        print e.args

        print "Writing Results to the Database"
        print "\nRestricted Found:", len(self.denied_urls), "Scanned:", len(self.found_urls) + len(self.denied_urls)
        print "\nThis can take quite a while to complete. DO NOT CLOSE THE PROGRAM until\nthis finishes or results will not be saved to the database. You will see a 'Done' message upon completion."
        for url in self.denied_urls:
            cursor.execute("UPDATE logs SET restricted = ?, scanned = ? WHERE url = ?", (1,1,url))
        for url in self.found_urls:
            cursor.execute("UPDATE logs SET restricted = ?, scanned = ? WHERE url = ? ", (0,1,url))
        print "Done"
        db.commit()
        db.close()
        pool.terminate()
        root.scan_running=False
        #root.html_thread.clear()
        self.clear()
        return      
        #message.showinfo(title="Complete", message="Scanning for restricted bugs is complete") 

class RootWindow(tk.Tk):
    newthread=False
    scan_running=False
    commit_track_list = []
    def __init__(self,*args,**kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        self.build_window()

    def build_window(self):
        # Build the Notebook widget
        n = ttk.Notebook(self)
        tab1 = ttk.Frame(n)
        tab2 = ttk.Frame(n)
        tab3 = ttk.Frame(n)
        tab4 = ttk.Frame(n)
        n.add(tab1,text="Welcome1")
        n.add(tab2,text="Parser")
        n.add(tab3,text="Results")
        n.add(tab4,text="Hosting")
        n.pack(fill="both", expand=True)

        # Populate tab1
        t1_frm1 = ttk.Frame(tab1)   
        t1_frm2 = ttk.Frame(tab1)
        t1_label1 = ttk.Label(t1_frm1,text="Welcome to the Webkit Bug Finder. This program will parse a WebKit SVN changelog and find all bugs that are\n\
restricted from public view. It stores the changelog information for each bug into a database so that the\n\
program can show you each bug and its associated committ log. Most of these will contain details about\n\
what triggers the bug. Many will also contain layout test paths to trigger the bug. These layout tests are\n\
contained in your updated local WebKit repo and can be hosted by this program using the hosting tab above.\n\
Once hosted, you can navigate your WebKit based browser to your_IP_address:8000 to see if the browser is\n\
affected by the bug. This is how it works:\n\n\
\n1: Update your local copy of WebKit repo by running Tools"+dir_slash+"Scripts"+dir_slash+"update-webkit\n\n\
2: You will need to have Subversion installed and obtain a svn changelog by navigating\n\
    to the root of your WebKit directory and running: svn log > any_filename.txt\n\n\
3: Once you have the svn changelog, you can parse and scan it following the instructions\n\
    in the parser tab. If this is the first time running the program, a new database will be\n\
    generated. If you already have a database, it will be updated each time you repeat this\n\
    process. Once a scan has completed it can take a while to write the results to the database.\n\
    You will see a 'Done' message in the terminal window when it has completed. ").pack(side='left',padx=5,pady=10)
        
        self.updt_wbkt_btn=ttk.Button(t1_frm2,text="Update WebKit",command=self.updt_wbkt_clicked).pack()
        t1_frm1.grid(column=1,row=1,padx=10,sticky='w')
        t1_frm2.grid(column=1,row=2,padx=10,sticky='sw')
        # Populate tab2
        frm1 = ttk.Frame(tab2)
        frm2 = ttk.Frame(tab2)
        frm3 = ttk.Frame(tab2)
        frm4 = ttk.Frame(tab2)
        frm5 = ttk.Frame(tab2)
        frm6 = ttk.Frame(tab2)
        frm7 = ttk.Frame(tab2)
        self.label1 = ttk.Label(frm1,text="Enter the path to the .txt log file you want to parse, or click Browse below.").pack(side='left',padx=5,pady=10)
        self.label2 = ttk.Label(frm2,text="Path:").pack(side='left',padx=5,pady=10)
        self.log_file_path = ttk.Entry(frm2, width=35)
        self.log_file_path.pack(side='left',padx=5,pady=10)
        self.browse_btn = ttk.Button(frm2,text="Browse..",command=self.browse_clicked).pack(side='left',padx=5,pady=10)
        self.label3 = ttk.Label(frm3,text="Once you've provided a valid path above, click on the Parse log button. This will parse the log file\ninto seperate commit entries and generate a database file to work with. This will take a few seconds.\nTo stop parsing when a specific date is reached, adjust the stop date accordingly. YYYY-MM-DD\nIf you are updating an existing database, the parser will automatically stop when it reaches the last\nknown commit found in the database OR when the stop date you provide is reached. Whichever\nhappens first.").pack(side='left',padx=5,pady=10)
        self.parse_btn = ttk.Button(frm4,text="Parse log",width=20,command=self.parse_clicked)
        self.parse_btn.pack(side='left',padx=5,pady=10)
        self.label7 = ttk.Label(frm4,text="Stop date:").pack(side='left',padx=20,pady=10)
        self.stop_year_box = ttk.Combobox(frm4,width=5,state='readonly',values=(range(2001,2020)))
        self.stop_year_box.pack(side='left',padx=2,pady=10)
        date_slash = ttk.Label(frm4,text='-').pack(side='left',padx=2,pady=10)
        self.stop_month_box = ttk.Combobox(frm4,width=3,state='readonly',values=(["%.2d"%i for i in range(1,13)]))
        self.stop_month_box.pack(side='left',padx=2,pady=10)
        date_slash2 = ttk.Label(frm4,text='-').pack(side='left',padx=2,pady=10)
        self.stop_date_box = ttk.Combobox(frm4,width=3,state='readonly',values=(["%.2d"%i for i in range(1,32)]))
        self.stop_date_box.pack(side='left',padx=2,pady=10)       
        self.label4 = ttk.Label(frm5,text="Once parsing/database generation completes, click on the Scan for restricted button. This will attempt\nto scan for all bugs that are protected. This can take a long time. You can throttle the slider below\nto adjust the scanning speed. This represents how many threads the scanner will spawn. The default\nis 12 and should be ok for most systems. Throttle this down if the scanning process fails. After\nthis completes, switch to the results tab at the top and click the refresh list button.").pack(side='left',padx=5,pady=10)
        self.scan_btn = ttk.Button(frm6,text="Scan for restricted bugs",width=20,command=self.scan_clicked)
        self.scan_btn.pack(side='left',padx=5,pady=10)
        self.label6 = ttk.Label(frm6,text="Throttle:").pack(side='left',padx=20,pady=10)
        self.throttler = tk.Scale(frm6,from_=1,to=15, length=325,tickinterval=1, orient='horizontal')
        self.throttler.pack(side='left',padx=1,pady=10)
        self.stop_scan_btn = ttk.Button(frm7,text='Stop scanning',width=20,command=self.stop_scan_clicked)
        self.stop_scan_btn.pack(side='left',padx=5)
        
        frm1.grid(column=1,row=1,padx=10,sticky='w')
        frm2.grid(column=1,row=2,padx=10,sticky='w')
        frm3.grid(column=1,row=3,padx=10,sticky='w')
        frm4.grid(column=1,row=4,padx=10,sticky='w')
        frm5.grid(column=1,row=5,padx=10,sticky='w')
        frm6.grid(column=1,row=6,padx=10,sticky='w')
        frm7.grid(column=1,row=7,padx=10,sticky='nw')
        self.stop_year_box.current(11)
        self.stop_month_box.current(9)
        self.stop_date_box.current(15)
        self.throttler.set(12)

        # Populate tab3
        frm8 = ttk.Frame(tab3)
        frm9 = ttk.Frame(tab3)   
        self.commit_view_box = tk.Listbox(frm8, height=39,width=35)
        self.commit_view_box.pack(fill='both',expand=True)
        self.commit_view_box.bind("<<ListboxSelect>>", self.commit_selected)
        self.commit_view_scrollbar = ttk.Scrollbar(self.commit_view_box,orient='vertical')
        self.commit_view_scrollbar.pack(side='right',fill='y')
        self.commit_view_box.config(yscrollcommand=self.commit_view_scrollbar.set)
        self.commit_view_scrollbar.config(command=self.commit_view_box.yview)
        self.results_box = ScrolledText(frm9,height=42,width=75,wrap='word')        
        self.results_box.pack(fill='both',expand=True)
        self.refresh_btn = ttk.Button(frm8,text='Refresh list',width=20,command=self.refresh_clicked)
        self.refresh_btn.pack(side='bottom',padx=50)
        frm8.pack(side='left',fill='both',expand=True)
        frm9.pack(side='right',fill='both',expand=True)

        # Populate tab4
        frm10 = ttk.Frame(tab4)
        frm11 = ttk.Frame(tab4)
        frm12 = ttk.Frame(tab4)
        frm13 = ttk.Frame(tab4)
        frm14 = ttk.Frame(tab4)
        frm15 = ttk.Frame(tab4)
        frm16 = ttk.Frame(tab4) 
        self.label6 = ttk.Label(frm10,text="Please enter your local IP address into the box below. You can attempt to grab your\nIP address automatically by clicking the Get my IP button.").pack(side='left',padx=5,pady=10)
        iplbl = ttk.Label(frm11,text='IP:').pack(side='left',padx=5,pady=10)
        self.localip_entry = ttk.Entry(frm11,width=30)
        self.localip_entry.pack(side='left',padx=5,pady=10)
        self.getip_btn = ttk.Button(frm11,text="Get my IP",width=20,command=self.getip_clicked)
        self.getip_btn.pack(side='left',padx=10,pady=10)
        self.label7 = ttk.Label(frm12,text="Next, provide the path to the layout tests directory below.").pack(side='left',padx=5,pady=10)
        self.label8 = ttk.Label(frm13,text="Path:").pack(side='left',padx=5,pady=10)
        self.layouttests_path = ttk.Entry(frm13, width=30)
        self.layouttests_path.pack(side='left',padx=5,pady=10)
        self.browse2_btn = ttk.Button(frm13,text="Browse..",command=self.browse2_clicked)
        self.browse2_btn.pack(side='left',padx=10,pady=10)
        self.label9 = ttk.Label(frm14,text="Now, simply switch to the results view and copy/paste the location of the layout test\nfile below. Then click the Host file button, This will rename and host the file as\nindex.html on port 8000, once hosting, point the console browser to\nyour_local_ip_address:8000. Be sure to stop the server when done").pack(side='left',padx=5,pady=10)
        self.label10 = ttk.Label(frm15,text="Paste:").pack(side='left',padx=5,pady=10)
        self.hostfile_entry = ttk.Entry(frm15, width=60)
        self.hostfile_entry.pack(side='left',padx=10,pady=10)
        self.host_btn = ttk.Button(frm16,text="Host file",width=20,command=self.host_file_clicked)
        self.host_btn.pack(side='left',padx=40,pady=10)
        self.stop_srvr_btn = ttk.Button(frm16,text="Stop server",width=20,command=self.stop_srvr_clicked)
        self.stop_srvr_btn.pack(side='left',padx=40,pady=10)
        frm10.grid(column=1,row=1,padx=10,sticky='w')
        frm11.grid(column=1,row=2,padx=10,sticky='w')
        frm12.grid(column=1,row=3,padx=10,sticky='w')
        frm13.grid(column=1,row=4,padx=10,sticky='w')
        frm14.grid(column=1,row=5,padx=10,sticky='w')
        frm15.grid(column=1,row=6,padx=10,sticky='w')
        frm16.grid(column=1,row=7,padx=10,sticky='w')

    # Behavior for button clicks in all tabs of root window.
    def updt_wbkt_clicked(self):
        print('not working yet')
        users_home = os.path.expanduser('~')
        wk = users_home+dir_slash+'WebKit'
        print(users_home)
        if os.path.isdir(wk):
            print('webkit directory exists at: '+wk)
        else:
            print('webkit was not present at: '+wk)
        
    def browse_clicked(self):
        log_path = filedialog.askopenfilename()
        self.log_file_path.delete('0',tk.END)
        self.log_file_path.insert('end',log_path)
   
    def browse2_clicked(self):        
        tests_directory = filedialog.askdirectory()
        self.layouttests_path.delete('0',tk.END)
        self.layouttests_path.insert('end',tests_directory)

    def start_server(self, path_to_host, local_ip, layout_loc, file_path):
        if not self.newthread:
                self.newthread = ServerThread(local_ip, path_to_host, layout_loc, file_path)
                self.newthread.daemon=True
                self.newthread.start()
                while True:
                    
                    if self.newthread.finished == True:
                        message.showinfo('Done','Now hosting '+ path_to_host + ' as\nindex.html @ '+str(self.newthread.serv_info[0])+":"+str(self.newthread.serv_info[1]))
                        break
                        
        else:
            message.showerror('Error','Server is already running.')
            print('server is running')
     
    def stop_srvr_clicked(self):
        if self.newthread:
            self.newthread.server.shutdown()
            self.newthread = False
            print('server stopped')
        else:
            print('server not found running')

    
    def getip_clicked(self):
        ip = ''
        if os.name == 'posix':
            ip = commands.getoutput("hostname -I")
            print(ip)
        elif os.name == 'nt':
            ip = socket.gethostbyname(socket.gethostname())
            print(ip)
        else:
            print('couldnt get local ip')
        self.localip_entry.delete('0',tk.END)
        self.localip_entry.insert('end',ip)
            
         

    def parse_clicked(self):
        try:
            log_path = open(self.log_file_path.get())
        except Exception as e:
            print(e)
            log_path=None
        if log_path != None:
            try:
                stop_date = self.stop_year_box.get()+'-'+self.stop_month_box.get()+'-'+self.stop_date_box.get()             
                self.parsed_log = LogParser(log_path,stop_date)
                self.commit_list = self.parsed_log.commit_list
                self.entry_count = self.parsed_log.entry_count
                message.showinfo('Complete','Operation is complete')
            except Exception as e:
                print(e)
                message.showerror('Error','Something went wrong parsing the log.')
        else:
            message.showerror('Error','You did not provide a file name or the file name is invalid.')

    def scan_clicked(self):
        if not self.scan_running:
                throttle_value = self.throttler.get()
                self.html_thread = HTMLScraper(int(throttle_value))
                self.html_thread.daemon=True
                self.html_thread.start()

    def stop_scan_clicked(self):
        print 'stop scanning'
        try:
            self.html_thread.abort = True
        except Exception as e:
            print(e.args)

    def refresh_clicked(self):
        db = sqlite3.connect(db_name)
        cursor = db.cursor()
        cursor.execute("SELECT * FROM logs WHERE restricted == 1")
        self.commit_view_box.configure(state='normal')
        self.commit_view_box.delete('0',tk.END)
        for i in cursor:
            self.commit_view_box.insert('end',i[1]+' | '+i[2])
            self.commit_track_list.append(i[1])
        db.close()
    '''
    def stripdb_clicked(self):
        
        db_id = []
        db = sqlite3.connect(db_name)
        cursor = db.cursor()
        cursor.execute("SELECT * FROM logs")
        try:
            for i in cursor:
                if i[4] != 1:
                    db_id.append(i[0])
            for i in db_id:
                cursor.execute("DELETE FROM logs WHERE id = ?",(str(i),))
        except Exception as e:
            print(e)
            message.showerror('Error','Something went wrong stripping the database.')
        message.showinfo('Complete','Operation complete')
        db.commit()
        db.close()
    '''
    def host_file_clicked(self):
        self.stop_srvr_clicked()
        local_ip = self.localip_entry.get()
        layout_loc = self.layouttests_path.get()
        if os.name =='nt':
                    layout_loc=layout_loc.replace('/',dir_slash)
        if local_ip != '':
            if layout_loc != '':
                file_path = self.hostfile_entry.get()
                if os.name =='nt':
                    file_path=file_path.replace('/',dir_slash)
                alt_file_path = layout_loc + dir_slash + file_path
                print('the file path : ' + file_path)
                if file_path != '':
                    try:
                        if os.path.isfile(alt_file_path):
                            self.start_server(alt_file_path, local_ip, layout_loc, file_path)
                            #self.copy_host_file(alt_file_path)
                            print('found file')
                            #message.showinfo('Done','Now hosting '+ alt_file_path)
                        else:
                            message.showerror('Error','File was not found.')
                    except Exception as e:
                        print(e)                       
                else:
                    message.showerror('Error','All fields are required.')    
            else:
                message.showerror('Error','All fields are required.')
        else:
            message.showerror('Error','All fields are required.')
    '''
    def copy_host_file(self,file_to_host):
        filename = "index.html"
        try:
            shutil.copyfile(file_to_host, filename)
        except Exception as e:
            print(e)
    '''
    # Behavior for the commit_view_box listbox selections.
    def commit_selected(self,event):
        self.results_box.delete('0.0',tk.END)    
        current = self.commit_view_box.curselection()
        activate_current = self.commit_view_box.activate(current)
        get_selection = current[0]
        #print "Selection", get_selection
        #print "Item", self.commit_track_list
        db = sqlite3.connect(db_name)
        cursor = db.cursor()
        cursor.execute("SELECT * FROM logs WHERE revision = ?",(self.commit_track_list[int(get_selection)],))
        results = cursor.fetchall()
        #print results
        if len(results) > 0:
             for result in results:
                lid,rvn,date,url,info,rst,scnd  = result
                #print "RVN:",rvn
                #print "DATE:",c
                #print "URL:",d
                try:
                    lid,rvn,date,url,info,rst,scnd = result
                    meta = rvn + '| ' + date + ' | ' + url
                    delimeter = '_'*55
                    self.results_box.insert('end','\n'.join([meta,delimeter,(info+ "\n")]))
                except Exception as e:
                    print e.args
                
        cursor.close()
        db.close()



if __name__ == '__main__':
    multiprocessing.freeze_support()
    root = RootWindow()
    root.title("Webkit Bug Finder v1.0")
    root.mainloop()
    


