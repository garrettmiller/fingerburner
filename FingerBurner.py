#!/usr/bin/python
####################################################################
#FingerBurner.py                                                   #
#Detection Script for Plugin-Based Fingerprinting, 2015            #
#Houston Hunt, Alejandro Jove, Garrett Miller, Haley Nguyen        #
#Other code/APIs borrowed are property of their respective authors.#
####################################################################

from datetime import datetime #Necessary for logging time
from collections import Counter
from libmproxy.script import concurrent #Enable concurrency to increase speed
from libmproxy.protocol.http import decoded #Enable decoding gzipped responses
import re #Needed to perform regex functions
import sys #Needed to exit with error status
try:
	import cPickle as pickle #Necessary to read our fontlist in from file
except:
	import pickle #cPickle is faster, but fall back to pickle if it's not there.

#Function to get fonts from pickle storage object.
def get_font_list ():
	fontList = pickle.load(open("fontlist.pickle", "rb"))
	good_font_test = re.compile("^[a-zA-Z0-9_ ]+$")
	temp_fonts = [f for f in fontList if good_font_test.match(f)]
	
	return temp_fonts
	
# Return a regular expression search pattern for every font in fontList
def build_font_regex (fontList):
	fontRe = [f.replace(" ", "[+ ]{1}") for f in fontList]
	reObjs = [re.compile(r) for r in fontRe]
	
	return reObjs

#Load fontList
fontList = get_font_list()
fontRe = build_font_regex(fontList)

#List of fonts to replace
default_fonts = pickle.load(open("common_fonts.pickle", "rb"))

#Regular expression pattern for plugin iterator string
pluginRe = re.compile("Plugin[+ ]{1}[0-9]+")

#Handle packet requests for mitmproxy. Runs concurrently for speed, 
#remove @concurrent if this is causing problems.
@concurrent
def request(context, flow):
	with decoded(flow.request):  #automatically decode gzipped responses.
		
		#Only run for POST or GET data responses, return otherwise
		if(flow.request.method != "POST" and flow.request.method != "GET"):
			return

		#Always make useragent more common, to reduce fingerprintability.
		useragent_spoof(flow.request.headers)
		
		#Do plugin detection detection, spoofing if necessary
		browserplugin_detect(flow.request)
		
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
		content.content = font_spoof(content.content)
	return content

#Function to do font list spoofing as part of a Flash or Java plugin response
def font_spoof(content):
	locations = {}
	
	for name, r in zip(fontList, fontRe):
		m = re.search(r, content)
		if m:
			locations[name] = (m.start(0), m.end(0))
		pass
	
	list_pos = [(k, v) for k, v in locations.items()]
	list_pos = sorted(list_pos, key=lambda item: item[1])
	
	# The most common distance between end of one font and start of another
	# should be the length of the delimiter
	dcount = Counter()
	dist2name  = {}
	
	for i in range(len(list_pos) - 1):
		name, pos = list_pos[i]
		nextname, nextpos = list_pos[i+1]
		d = nextpos[0] - pos[1]
		dcount[d] += 1
		dist2name[d] = name
		pass
	
	delimiter_len = dcount.most_common(1)[0][0]
	name = dist2name[delimiter_len]
	index = content.find(name)
	
	if index == -1:
		print "Something terrible has happened. Can't find existing font, exiting:", name 
		sys.exit(-1)
		pass
	
	start = index + len(name)
	end = start + delimiter_len
	delimiter = content[start:end]
	
	# Detecting whether another character is used for space
	replaced_space = " "
	for name, r in zip(fontList, fontRe):
		# We need to find a space character to test if another character is used
		if name.find(" ") == -1:
			continue
		
		m = re.search(r, content)
		if m:
			font_in_content = m.group(0)
			space_index = name.find(" ")
			replaced_space = font_in_content[space_index]
			break
		pass

	# Replace this chunk of detect fonts to our default_fonts
	start = list_pos[0][1][0]
	end = list_pos[-1][1][1]
	
	# First, replace the space in our fonts with replaced_space
	for i in range(len(default_fonts)):
		f = default_fonts[i]
		default_fonts[i] = f.replace(" ", replaced_space)
		pass
	
	content = "%s%s%s" % (content[:start], delimiter.join(default_fonts),
						content[end:])
	return content

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
	pluginList = ['Shockwave', 'Flash', 'Silverlight', 'Plug-In', 'plugins',
	'Chrome PDF Viewer', 'Native Client', 'NaCl', 'Widevine Content Decryption Module', 
	'Widevine', 'FutureSplash Player', 'VLC Web Plugin', 'Adobe Reader',
	'Chrome Remote Desktop Viewer', 'Unity Web Player']
	
	#Initialize num_match for iterating through plugin list
	num_match = 0
	
	#Iterate through font list to see if our font was found therein.
	for p in pluginList:
		if p in str(content.content):
			num_match += 1
			
	#If we see a lot of words matching plugins in response, 
	#plugin fingerprinting is likely happening.
	#If we have less than 3, we're probably not unique enough to fingerprint.
	#Write to logfile for fingerprinting.
	if num_match >= 3:
		print "Plugin fingerprinting detected"
		f3 = open ("plugin_log.txt", "a")
		f3.write("----------%s----------\n" % str(datetime.now()))
		f3.write("URL: %s\n" % content.pretty_url(True))
		f3.write("CONTENT: %s\n" % content.content)
		f3.write("PLUGINS FOUND: %d\n" % (num_match))
		f3.close()
		#Do plugin spoofing, if plugin detection detected.
		content.content = browserplugin_spoof(content.content)
	
# This function defeats only BrowserSpy library's plugin detection because it
# detects only the iterator pattern of BrowserSpy, which is "Plugin <number>:"
# for plugin.
# Due to the heterogeneous nature of plugin names (there is a mixture of
# alphabetical character, numbers, underscore, hypens, period, semi-colon, 
# commas, backslash, colon, and many other characters), detecting an iterator
# pattern for plugin is difficult, so we opted to defeat only browserspy's for
# now. This is still valuable because browserspy is a popular library.
def browserplugin_spoof(content):
	matches = re.findall(pluginRe, content)
	
	if matches and len(matches) > 1:
		m_first = matches[0]
		m_last = matches[-1]
		
		index_first = content.find(m_first)
		index_last = content.find(m_last)
		
		# Grab the plugin number and change it to 0 since there is only
		# one plugin left, this should be fine
		colon_index = content[index_last:].find(":")
		if colon_index == -1:
			colon_index = content[index_last:].find("%")
			pass
		
		colon_index += index_last
		content = "%sPlugin 0%s" % (content[:index_first], 
								content[colon_index:])
		pass
	
	return content
