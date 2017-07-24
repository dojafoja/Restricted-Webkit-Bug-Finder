# Restricted-Webkit-Bug-Finder

Will parse a WebKit svn changelog and create/update a database with individual commits. The database is then querried and all bug urls are scanned to find the ones that are restricted from public view, these ones get marked in the database as restricted. This program will present ONLY the restricted bugs in a nice gui listview. It also allows for easy testing of the bugs that have layout tests available by copy/pasting the layout test path right into the hosting tab of the program. Click host and then navigate the WebKit device to "your_local_ip:8000" and the layout test is triggered. If the browser crashes, behaves funny, or fails the test it may be worth looking into.

This program works best on linux, mostly because the program can automate the entire process for you on linux if you have subversion installed and a have a copy of the WebKit repo @ /home/user/WebKit. It works fine on Windows too but you will need to manually update WebKit and manually obtain a svn changelog, instructions found below.

USAGE:

The whole process can take quite some time depending on how far back you are parsing the log. Be patient! lol

1. First you will want to checkout a local copy of the WebKit repo found here: http://www.webkit.org/building/checkout.html 
For Linux users, be sure to have this located at /home/user/WebKit/

2. Next you will want to have subversion installed on your system: https://subversion.apache.org/

3. This program requires Python 2.7 to run so download and install it from here if you don't already have it: https://www.python.org/downloads/

4. You will need one, possibly two external libraries. The first is BeautifulSoup4 found here: https://www.crummy.com/software/BeautifulSoup/ and the second is Tkinter. Tkinter ships with Python so you probably won't need to install it but some Linux distro's don't come with it. Install it using something like "sudo apt-get install python-tk" without the quotes, of course.

5. Always start with an updated WebKit repo and svn changelog each time you use the program. If you are on Linux and have WebKit located at /home/user/WebKit and you have subversion installed, move on to step 6. Otherwise update your WebKit repo, either by doing a fresh checkout or executing the bash script located at WebKit/Tools/Scripts/update-webkit, you will also need to obtain a svn changelog by running: "svn log > any_file_name.txt". You need to run this command inside your working copy of WebKit for it to work. 

6. Launch this program with Python. In Windows you should be able to double click main.py. In Linux open terminal and navigate to where you downloaded this program and run: "python main.py". If you are running Linux and are going to use the Automate feauture, FIRST switch to the parser tab of the program and adjust the stop date and throttle accordingly. The stop date is how far back the log will be parsed and the throttle is how many processes are spawned to do the scanning. Then switch back to the Welcome tab and click Automate, when done skip to step 8. Otherwise switch to the parser tab and click browse. Provide the path to the svn changelog you just acquired, adjust the stop date and click parse.

7. After parsing has completed, we will scan all the bugs to find ones which are restricted from public view. Adjust the throttle accordingly and click on the scan for restricted button. This can take a VERY long time, especially if you are parsing pretty far back in the log. It will display it's progress and when it's done, you will see a Done message appear in the terminal.

8. Once scanning is completed, switch to the results tab and click refresh list button on bottom left of window. This will show you all bugs that are restricted in the database. Select a bug on the left to see it's commit log on the right. There is a lot of useful info to be found here. Sometimes they will even have layout tests that trigger the bug. If there is a layout test available and you would like to test the bug on a WebKit browser, move to step 9.

9. If you have found a bug that contaings a layout test and you would like to see if your WebKit browser is affected by it, switch to the hosting tab of the program. Either provide the IP addresss to your computer that is runnng this program OR click on the Get my IP button to automatically find your IP address. Next, click browse and tell the program where the layout tests directory is located, this should be at WebKit/LayoutTests. Once that information is provided then switch back to the results tab and copy the path to the layout test that is provided in the commit log using Ctrl-C. Switch back to the hosting tab and paste the test path using Ctrl-V and then click the host file button. The layout test is now being hosted locally on your PC at your_ip_address:8000. Lets say for example that your IP address is 192.168.1.217, you would use your WebKit browser and point it to 192.168.1.217:8000 and the layout test will be loaded. Personally I would create a bookmark on the WebKit browser for your IP address and select it. If it passes the test, doesn't crash or behave funny then go back to the program, find a new layout test, host it, test it! Wash, rinse, repeat!

10. Each time a scan is run, either a new commits.db database file will be created or if one already exists it acts as a cache and scanning for bugs will resume from the higest revison contained in the database. This is useful for periodically checking for new bugs. If you want a clean slate every time, then simply delete or rename the commits.db file.

10. That's it, I hope you enjoy this program as much as we did creating it. A big huge THANK YOU goes to Onion_knight from gbatemp for his contributions to this program. He greatly improved the parsing abilities as well as implementing the multiprocess scannning portion. He also added the time remaining calculations. This program would be very slow and not as reliable if it weren't for him.  


