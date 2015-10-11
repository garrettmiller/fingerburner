import re
from datetime import datetime
from collections import Counter

#mitmproxy -s detect.py --anticache

fontList = ["Times New Roman", "Copperplate", "Arial", "Calibri", "Sans", "Papyrus",
"Perpetua", "Gotham", "Serif", "Book Antiqua", "Garamond", "Baskerville",
"Century Schoolbook", "Gothic", "Optima"]


regExp = [re.compile(f) for f in fontList]

#def start(context, argv):
#	pass

#Handle packet requests
def request(context, flow):
	
	if(flow.request.method != "POST"):
		return

	f1 = open("log.txt", "a")
	f1.write("%s\n" % (flow.request.pretty_url(True)))
	f1.write("%s\n" % (flow.request.content))
	f1.write("%s\n" % (flow.request.method))

	f1.close()

	num_match = 0
	#print(flow.request)

	for i in range(len(regExp)):
		x = regExp[i]

		if x.search(flow.request.content):
			num_match += 1
			pass
		pass


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



def font_spoof(content):

	delimiter_list = []

	#build a list of characters found after a font to find delimiter
	for i in range(len(regExp)):
		x = regExp[i]
		if x.search(content):
			last_index = content.rfind(x.search(content).group(0))
			delimiter_list.append(content[last_index + len(x.search(content).group(0))])
			pass
		pass

	delimiter_list = Counter(delimiter_list)

	#get the most common character (the delimiter)
	for key in delimiter_list.most_common(1):
		print "delimiter is %s\n" % (str(key[0]))
		delimiter = str(key[0]])
		pass
	pass



	#random.seed()
	#random.randint(0, len(fontList))




