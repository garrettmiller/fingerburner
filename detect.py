#!/usr/bin/python
####################################################################
#detect.py                                                         #
#Detection Script for Plugin-Based Fingerprinting, 2015            #
#Houston Hunt, Alejandro Jove, Garrett Miller, Haley Nguyen        #
#Other code/APIs borrowed are property of their respective authors.#
####################################################################

from datetime import datetime #Necessary for logging time
from collections import Counter
from libmproxy.script import concurrent #Enable concurrency to increase speed
from libmproxy.protocol.http import decoded #Enable decoding gzipped responses
try:
	import cPickle as pickle #Necessary to read our fontlist in from file
except:
	import pickle #cPickle is faster, but fall back to pickle if it's not there.

#Load fontList
fontList = pickle.load(open("fontlist.pickle", "rb"))

#Handle packet requests for mitmproxy. Runs concurrently for speed, 
#remove @concurrent if this is causing problems.
@concurrent
def request(context, flow):
	with decoded(flow.request):  #automatically decode gzipped responses.
		
		#Only run for POST or GET data responses, return otherwise
		if(flow.request.method != "POST" and flow.request.method != "GET"):
			return
			
		#Write logfile for browsing, likely will remove this for final deliverable.
		f1 = open("log.txt", "a")
		f1.write("%s\n" % (flow.request.pretty_url(True)))
		f1.write("%s\n" % (flow.request.content))
		f1.write("%s\n" % (flow.request.method))
		f1.close()

		#Always make useragent more common, to reduce fingerprintability.
		useragent_spoof(flow.request.headers)
		
		#Do plugin detection detection, spoofing if necessary
		browserplugin_detect()
		
		#Do font detection, spoofing if necessary
		font_detect(flow.request)

#Function to detect font fingerprinting
def font_detect(content):
	#Initialize num_match for iterating through font list
	num_match = 0

	#Iterate through font list to see if our font was found therein.
	for f in fontList:
		if f in str(content.content):
			num_match += 1

	#If we see a lot of words matching fonts in response, 
	#font fingerprinting is likely happening.
	#Write to logfile for fingerprinting.
	if num_match >= 5:
		print "Font fingerprinting detected"
		f2 = open ("fp_log.txt", "a")
		f2.write("----------%s----------\n" % str(datetime.now()))
		f2.write("URL: %s\n" % content.pretty_url(True))
		f2.write("CONTENT: %s\n" % content.content)
		f2.write("FONTS FOUND: %d\n" % (num_match))
		f2.close()
		#Do font spoofing, if font detection detected.
		font_spoof(content.content)
	return content

#Function to do font list spoofing as part of a Flash or Java plugin response
def font_spoof(content):
	#Initialize empty list of possible delimiters
	delimiter_list = []
	
	#Alejandro - let's talk about this, we can rework based on new method of list iterating. - Garrett
	#Build a list of characters found after a font to find delimiter
	#for f in fontList:
		#if f in str(content):

			#last_index = content.rfind(x.search(content).group(0))
			#delimiter_list.append(content[last_index + len(x.search(content).group(0))])
		
	delimiter_list = Counter(delimiter_list)

	#Get the most common character (the delimiter)
	for key in delimiter_list.most_common(1):
		print "delimiter is %s\n" % (str(key[0]))
		delimiter = str(key[0])

	#Do something with delimiter

	#random.seed()
	#random.randint(0, len(fontList))

#Function to do useragent spoofing
#Sourced from https://techblog.willshouse.com/2012/01/03/most-common-user-agents/ on 10/16/2015.
#Too few people use Linux, it makes you unique. Thus, omitting and defaulting to OS X.
def useragent_spoof(headers):
	#Check browser type, then assign to a common version.
	if "Chrome" in str(headers['User-Agent']):
		if "Windows" in str(headers['User-Agent']):
			#Windows 7 and Chrome 45
			headers['User-Agent'] = ['Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36']
		else:
			#OS X 10.10.5 and Chrome 45
			headers['User-Agent'] = ['Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36']
	
	elif "Firefox" in str(headers['User-Agent']):
		if "Windows" in str(headers['User-Agent']):
			#Windows 7 and Firefox 40
			headers['User-Agent'] = ['Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0']
		else:
			#OS X 10.10 and Firefox 40.0
			headers['User-Agent'] = ['Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:40.0) Gecko/20100101 Firefox/40.0']
	
	elif "Trident" in str(headers['User-Agent']):
		#MSIE 11 and Windows 7
		headers['User-Agent'] = ['Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko']
	
	else:
		#OS X 10.10.5 and Safari 8.0
		headers['User-Agent'] = ['Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/8.0.8 Safari/600.8.9']

#Function to do browser plugin list detection as part of a JS response.
def browserplugin_detect(content):
	pass
	
#Function to do browser plugin list spoofing if necessary.
def browserplugin_spoof(content):
	pass