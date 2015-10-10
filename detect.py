import re

fontList = ["Times New Roman", "Copperplate", "Arial", "Calibri", "Sans", "Papyrus",
"Perpetua", "Gotham", "Serif", "Book Antiqua", "Garamond", "Baskerville",
"Century Schoolbook", "Gothic", "Optima"]


regExp = [re.compile(f) for f in fontList]

#def start(context, argv):
#	pass

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
		f = fontList[i]

		if x.search(flow.request.content):
			num_match += 1
			pass
		pass

	print "matches: ", num_match

	if num_match >= 5:
		print "Font fingerprinting"
		f2 = open ("fp_log.txt", "a")
		f2.write("%s\n" % flow.request.pretty_url(True))
		f2.write("%s\n" % flow.request.content)
		f2.write ("fonts found %d\n" % (num_match))
		f2.close()
		pass
	pass


