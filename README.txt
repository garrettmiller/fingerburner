*****************************************************************
*FingerBurner - Thwarting Plugin-based Browser Fingerprinting   *
*Houston Hunt, Alejandro Jove, Garrett Miller, Haley Nguyen     *
*94-806, Fall 2015, Carnegie Mellon University                  *
*****************************************************************

=========================================================
INSTALLING:
=========================================================
Under OS X (using Homebrew):
----------------------------
ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
brew install python
pip install pyasn1 pyOpenSSL mitmproxy
-----------------------------

Under Ubuntu 14.04 or newer:
----------------------------
sudo apt-get install python-pip python-dev libffi-dev libssl-dev libxml2-dev libxslt1-dev
sudo pip install pyasn1 pyOpenSSL mitmproxy
sudo pip install pyOpenSSL --upgrade
-----------------------------

Under Windows 7 or newer:
-----------------------------
Install Python 2.7.10 (includes pip) - https://www.python.org/downloads/
Open a command prompt and run the following: 
	C:\Python27\Scripts\pip install pyasn1 pyOpenSSL mitmproxy --upgrade
-----------------------------

Test installation by running:
	pydoc libmproxy.protocol.http.HTTPRequest

If you can view the document for the HTTPRequest class then you have installed
everything successfully.

=========================================================
RUNNING:
=========================================================
Run the proxy on your local computer (from the FingerBurner directory):
	OSX, Linux: ./main.sh
	
	Windows: main.bat

Configure your browser to use HTTP proxy "localhost" on port 8080.
	Check the box to use this proxy for all protocols.

Navigate to http://mitm.it, and install the SSL certificate by following 
the on-screen instructions for your operating system to enable SSL protection.

For more info see https://mitmproxy.org/doc/certinstall.html

=========================================================
RUNNING WEB CRAWLER:
=========================================================
First, install scrapy with pip:
	sudo pip install scrapy

Set ulimit -n 1024, and ulimit -u 1024.
How to set this is dependent on your system, but on Mac OSX 10.9, I put these commands
.bash_profile.

Then in the fingerburner/webcrawler directory, run:
	scrapy crawl webcrawler -a pattern=url_pattern.txt

Give it some time, and run Ctrl-C only once

The crawler will nicely clean up and leave a webcrawler_urls.txt file in the 
working directory. This file will contain a list of URLs of distinct sub-domains.
For example:
http://loveemerald.deviantart.com
AND
http://le-vampire-cat.deviantart.com
ARE CONSIDERED DISTINCT.

=========================================================
ACKNOWLEDGEMENTS:
=========================================================
The mitmproxy Project:
https://mitmproxy.org/

The pyOpenSSL Project:
https://github.com/pyca/pyopenssl

Alessandro Acquisti and the teaching staff of 94-806, Privacy in the Digital Age, at Carnegie Mellon University.