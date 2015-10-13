#!/usr/bin/python
####################################################################
#detect.py                                                         #
#Detection Script for Plugin-Based Fingerprinting, 2015            #
#Houston Hunt, Alejandro Jove, Garrett Miller, Haley Nguyen        #
#Other code/APIs borrowed are property of their respective authors.#
#USAGE: mitmproxy -s detect.py --anticache                         #
####################################################################

import re
from datetime import datetime
from collections import Counter

#Establish a list of fonts to compare against to detect fingerprinting
fontList = ["Times New Roman", "Copperplate", "Arial", "Calibri", "Sans", "Papyrus",
"Perpetua", "Gotham", "Serif", "Book Antiqua", "Garamond", "Baskerville",
"Century Schoolbook", "Gothic", "Optima"]

regExp = [re.compile(f) for f in fontList]

#Handle packet requests for mitmproxy
def request(context, flow):
	
	#Only run for POST data responses, return otherwise
	if(flow.request.method != "POST"):
		return

	#Write logfile for browsing, likely will remove for deliverable.
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
		x = regExp[i]
		if x.search(flow.request.content):
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
		x = regExp[i]
		if x.search(content):
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
def useragent_spoof():



