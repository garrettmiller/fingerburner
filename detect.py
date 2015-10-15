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

#Establish a list of fonts to compare against to detect fingerprinting
fontList = ['Agency FB', 'Algerian', 'Arial', 'Arial Black', 'Arial Narrow', 'Arial Rounded MT Bold', 'Arial Unicode MS', 'Baskerville Old Face', 'Bauhaus 93', 'Bell MT', 'Berlin Sans FB', 'Berlin Sans FB Demi', 'Bernard MT Condensed', 'Blackadder ITC', 'Bodoni MT', 'Bodoni MT Black', 'Bodoni MT Condensed', 'Bodoni MT Poster Compressed', 'Book Antiqua', 'Bookman Old Style', 'Bookshelf Symbol 7', 'Bradley Hand ITC', 'Britannic Bold', 'Broadway', 'Brush Script MT', 'Caladea', 'Calibri', 'Calibri Light', 'Californian FB', 'Calisto MT', 'Cambria', 'Cambria Math', 'Candara', 'Carlito', 'Castellar', 'Centaur', 'Century', 'Century Gothic', 'Century Schoolbook', 'Chiller', 'Colonna MT', 'Comic Sans MS', 'Consolas', 'Constantia', 'Cooper Black', 'Copperplate Gothic Bold', 'Copperplate Gothic Light', 'Corbel', 'Courier', 'Courier New', 'Curlz MT', 'DejaVu Sans', 'DejaVu Sans Condensed', 'DejaVu Sans Light', 'DejaVu Sans Mono', 'DejaVu Serif', 'DejaVu Serif Condensed', 'Ebrima', 'Edwardian Script ITC', 'Elephant', 'Engravers MT', 'Eras Bold ITC', 'Eras Demi ITC', 'Eras Light ITC', 'Eras Medium ITC', 'Felix Titling', 'Fixedsys', 'Footlight MT Light', 'Forte', 'Franklin Gothic Book', 'Franklin Gothic Demi', 'Franklin Gothic Demi Cond', 'Franklin Gothic Heavy', 'Franklin Gothic Medium', 'Franklin Gothic Medium Cond', 'Freestyle Script', 'French Script MT', 'Gabriola', 'Gadugi', 'Garamond', 'Gentium Basic', 'Gentium Book Basic', 'Georgia', 'Gigi', 'Gill Sans MT', 'Gill Sans MT Condensed', 'Gill Sans MT Ext Condensed Bold', 'Gill Sans Ultra Bold', 'Gill Sans Ultra Bold Condensed', 'Gloucester MT Extra Condensed', 'Goudy Old Style', 'Goudy Stout', 'Haettenschweiler', 'Harlow Solid Italic', 'Harrington', 'High Tower Text', 'Impact', 'Imprint MT Shadow', 'Informal Roman', 'Javanese Text', 'Jokerman', 'Juice ITC', 'Kristen ITC', 'Kunstler Script', 'Leelawadee UI', 'Leelawadee UI Semilight', 'Liberation Mono', 'Liberation Sans', 'Liberation Sans Narrow', 'Liberation Serif', 'Linux Biolinum G', 'Linux Libertine Display G', 'Linux Libertine G', 'Lucida Bright', 'Lucida Calligraphy', 'Lucida Console', 'Lucida Fax', 'Lucida Handwriting', 'Lucida Sans', 'Lucida Sans Typewriter', 'Lucida Sans Unicode', 'Magneto', 'Maiandra GD', 'Malgun Gothic', 'Malgun Gothic Semilight', 'Marlett', 'Matura MT Script Capitals', 'Microsoft Himalaya', 'Microsoft JhengHei', 'Microsoft JhengHei Light', 'Microsoft JhengHei UI', 'Microsoft JhengHei UI Light', 'Microsoft New Tai Lue', 'Microsoft PhagsPa', 'Microsoft Sans Serif', 'Microsoft Tai Le', 'Microsoft YaHei', 'Microsoft YaHei Light', 'Microsoft YaHei UI', 'Microsoft YaHei UI Light', 'Microsoft Yi Baiti', 'MingLiU-ExtB', 'MingLiU_HKSCS-ExtB', 'Mistral', 'Modern', 'Modern No. 20', 'Mongolian Baiti', 'Monotype Corsiva', 'MS Reference Sans Serif', 'MS Reference Specialty', 'MS Sans Serif', 'MS Serif', 'MT Extra', 'MV Boli', 'Myanmar Text', 'Niagara Engraved', 'Niagara Solid', 'Nirmala UI', 'Nirmala UI Semilight', 'NSimSun', 'OCR A Extended', 'Old English Text MT', 'Onyx', 'Open Sans', 'OpenSymbol', 'Palace Script MT', 'Palatino Linotype', 'Papyrus', 'Parchment', 'Perpetua', 'Perpetua Titling MT', 'Playbill', 'PMingLiU-ExtB', 'Poor Richard', 'Pristina', 'PT Serif', 'Rage Italic', 'Ravie', 'Rockwell', 'Rockwell Condensed', 'Rockwell Extra Bold', 'Roman', 'Script', 'Script MT Bold', 'Segoe MDL2 Assets', 'Segoe Print', 'Segoe Script', 'Segoe UI', 'Segoe UI Black', 'Segoe UI Emoji', 'Segoe UI Historic', 'Segoe UI Light', 'Segoe UI Semibold', 'Segoe UI Semilight', 'Segoe UI Symbol', 'Showcard Gothic', 'SimSun', 'SimSun-ExtB', 'Sitka Banner', 'Sitka Display', 'Sitka Heading', 'Sitka Small', 'Sitka Subheading', 'Sitka Text', 'Small Fonts', 'Snap ITC', 'Source Code Pro', 'Source Sans Pro', 'Source Sans Pro Black', 'Source Sans Pro ExtraLight', 'Source Sans Pro Light', 'Source Sans Pro Semibold', 'Stencil', 'Sylfaen', 'Symbol', 'System', 'Tahoma', 'TeamViewer10', 'Tempus Sans ITC', 'Terminal', 'Times New Roman', 'Trebuchet MS', 'Tw Cen MT', 'Tw Cen MT Condensed', 'Tw Cen MT Condensed Extra Bold', 'Verdana', 'Viner Hand ITC', 'Vivaldi', 'Vladimir Script', 'Webdings', 'Wide Latin', 'Wingdings', 'Wingdings 2', 'Wingdings 3', 'Yu Gothic', 'Yu Gothic Light', 'Yu Gothic Medium', 'Yu Gothic UI', 'Yu Gothic UI Light', 'Yu Gothic UI Semibold', 'Yu Gothic UI Semilight', 'Yu Mincho', 'Yu Mincho Demibold', 'Yu Mincho Light', 'KacstFarsi', 'Droid Sans Armenian', 'Meera', 'FreeMono', 'Padauk Book', 'Loma', 'Droid Sans', 'Century Schoolbook L', 'KacstTitleL', 'Ubuntu Medium', 'Droid Arabic Naskh', 'OpenDyslexic', 'Garuda', 'Rekha', 'Purisa', 'DejaVu Sans Mono', 'Droid Sans Mono', 'Vemana2000', 'KacstOffice', 'Umpush', 'OpenSymbol', 'Sawasdee', 'Droid Sans Ethiopic', 'Tibetan Machine Uni', 'URW Palladio L', 'FreeSerif', 'KacstDigital', 'Ubuntu Condensed', 'Droid Arabic Kufi', 'mry_KacstQurn', 'Padauk', 'URW Gothic L', 'Droid Sans Georgian', 'Dingbats', 'URW Chancery L', 'Phetsarath OT', 'Droid Sans Japanese', 'Tlwg Typist', 'KacstLetter', 'utkal', 'Norasi', 'Droid Sans Fallback', 'OpenDyslexicMono', 'KacstOne', 'Liberation Sans Narrow', 'NanumMyeongjo', 'Lohit Gujarati', 'Liberation Mono', 'KacstArt', 'Mallige', 'Bitstream Charter', 'NanumGothic', 'Liberation Serif', 'Ubuntu', 'Courier 10 Pitch', 'Nimbus Sans L', 'Droid Sans Hebrew', 'TakaoPGothic', 'DejaVu Sans', 'Kedage', 'NanumBarunGothic', 'Kinnari', 'TlwgMono', 'Standard Symbols L', 'Lohit Punjabi', 'Nimbus Mono L', 'Rachana', 'Waree', 'KacstPoster', 'Khmer OS', 'FreeSans', 'gargi', 'Droid Sans Arabic', 'Nimbus Roman No9 L', 'DejaVu Serif', 'Ubuntu Light', 'TlwgTypewriter', 'KacstPen', 'Laksaman', 'Lohit Devanagari', 'Tlwg Typo', 'Droid Serif', 'Mukti Narrow', 'Droid Naskh Shift Alt', 'Ubuntu Mono', 'Lohit Bengali', 'Liberation Sans', 'KacstDecorative', 'Khmer OS System', 'Saab', 'Mukti Narrow', 'Symbola', 'KacstTitle', 'LKLUG', 'Abyssinica SIL', 'OpenDyslexicAlta', 'KacstQurn', 'URW Bookman L', 'KacstNaskh', 'KacstScreen', 'Pothana2000', 'Lohit Tamil', 'KacstBook']

#Handle packet requests for mitmproxy. Runs concurrently for speed, 
#remove @concurrent if this is causing problems.
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

		#Initialize num_match for iterating through font list
		num_match = 0

		#Iterate through font list to see if our font was found therein.
		for f in fontList:
			if f in str(flow.request.content):
				num_match += 1

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
#Sourced from https://techblog.willshouse.com/2012/01/03/most-common-user-agents/ on 8/14/2015.
#Too few people use Linux, it makes you unique. Thus, omitting and defaulting to OS X.
def useragent_spoof(headers):
	#Check browser type, then assign to a common version.
	if "Chrome" in str(headers['User-Agent']):
		#OS X 10.10.5 and Chrome 45
		headers['User-Agent'] = ['Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36']
	elif "Firefox" in str(headers['User-Agent']):
		#OS X 10.10 and Firefox 40.0
		headers['User-Agent'] = ['Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:40.0) Gecko/20100101 Firefox/40.0']
	else:
		#OS X 10.10.5 and Safari 8.0
		headers['User-Agent'] = ['Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/8.0.8 Safari/600.8.9']
	