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

Test installation by running:
	pydoc libmproxy.protocol.http.HTTPRequest

If you can view the document for the HTTPRequest class then you have installed
everything successfully.

=========================================================
RUNNING:
=========================================================
Run the proxy on your local computer:
	./main.sh

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

Then in the fingerburner/webcrawler directory, run:
	scrapy crawl webcrawler -a pattern=url_pattern.txt

Give it some time, and run Ctrl-C only once

The crawler will nicely clean up and leave a data.csv file in the working directory.
That file will contain a list of URLs of distinct domains.

=========================================================
ACKNOWLEDGEMENTS:
=========================================================
The mitmproxy Project:
https://mitmproxy.org/

The pyOpenSSL Project:
https://github.com/pyca/pyopenssl

Alessandro Acquisti and the teaching staff of 94-806, Privacy in the Digital Age, at Carnegie Mellon University.