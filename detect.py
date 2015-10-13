#!/usr/bin/python
####################################################################
#detect.py                                                         #
#Detection Script for Plugin-Based Fingerprinting, 2015            #
#Houston Hunt, Alejandro Jove, Garrett Miller, Haley Nguyen        #
#Other code/APIs borrowed are property of their respective authors.#
#USAGE: mitmproxy -s detect.py --anticache                         #
####################################################################

import re
from datetime import datetime #Necessary for logging time
from collections import Counter
from libmproxy.script import concurrent #Enable concurrency to increase speed
from libmproxy.protocol.http import decoded #Enable decoding gzipped responses

#Establish a list of fonts to compare against to detect fingerprinting
fontList = ["Times New Roman", "Copperplate", "Arial", "Calibri", "Sans", "Papyrus",
"Perpetua", "Gotham", "Serif", "Book Antiqua", "Garamond", "Baskerville",
"Century Schoolbook", "Gothic", "Optima"]

regExp = [re.compile(f) for f in fontList]

#Handle packet requests for mitmproxy. Runs concurrently
#for speed, remove @concurrent if this is causing problems.
@concurrent
def request(context, flow):
	with decoded(flow.request):  #automatically decode gzipped responses.
		
		#Only run for POST or GET data responses, return otherwise
		if(flow.request.method != "POST" and flow.request.method != "GET"):
			return

		#Always make useragent more common, to reduce fingerprintability.
		spoofed_content = useragent_spoof(flow.request.headers)

		#Write logfile for browsing, likely will remove this for final deliverable.
		f1 = open("log.txt", "a")
		f1.write("%s\n" % (flow.request.pretty_url(True)))
		f1.write("%s\n" % (flow.request.content))
		f1.write("%s\n" % (flow.request.method))
		f1.close()

		#DEBUG statement to see flow request
		#print(flow.request)

		#Initialize num_match for iterating through font list
		num_match = 0

		#Iterate through font list to see if our font was found therein.
		for i in range(len(regExp)):
			if regExp[i].search(flow.request.content):
				num_match += 1
				pass
			pass

		#If we see a lot of words matching fonts in response, 
		#font fingerprinting is likely happening.
		#Write to logfile for fingerprinting.
		if num_match >= 5:
			print "Font fingerprinting detected"
			f2 = open ("fp_log.txt", "a")
			f2.write("----------%s----------\n" % str(datetime.now()))
			f2.write("URL: %s\n" % flow.request.pretty_url(True))
			f2.write("CONTENT: %s\n" % flow.request.content)
			f2.write("FONTS FOUND: %d\n" % (num_match))
			f2.close()
			spoofed_content = font_spoof(flow.request.content)
			pass
		pass

#Function to do font list spoofing as part of a Flash or Java plugin response
def font_spoof(content):
	#Initialize empty list of possible delimiters
	delimiter_list = []

	#Build a list of characters found after a font to find delimiter
	for i in range(len(regExp)):
		if regExp[i].search(content):
			last_index = content.rfind(x.search(content).group(0))
			delimiter_list.append(content[last_index + len(x.search(content).group(0))])
			pass
		pass

	delimiter_list = Counter(delimiter_list)

	#Get the most common character (the delimiter)
	for key in delimiter_list.most_common(1):
		print "delimiter is %s\n" % (str(key[0]))
		delimiter = str(key[0])
		pass
	pass

	#Do something with delimiter

	#random.seed()
	#random.randint(0, len(fontList))

#Function to do useragent spoofing
#TODO - We'll likely want to find a list of most common ones, set ourselves to that
#or just minimize the amount of minor version numbers we're sending. 
def useragent_spoof(headers):
	#Check browser type, then assign to a common version. Placeholders for now.
	if "Chrome" in str(headers['User-Agent']):
		headers['User-Agent'] = ['CommonChrome']
	elif "Firefox" in str(headers['User-Agent']):
		headers['User-Agent'] = ['CommonFirefox']
	elif "Safari" in str(headers['User-Agent']):
		headers['User-Agent'] = ['CommonSafari']
	elif "MSIE" in str(headers['User-Agent']):
		headers['User-Agent'] = ['CommonIE']
	




