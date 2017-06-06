import sys
import urllib
import urllib.request

fullurl = input(“Please specify the full vulnerable url:  “)

for carg in sys.argv:

	if carg == “-w”:

		argnum = sys.argv.index(carg)

		argnum += 1

		fullurl = sys.argv[argnum]
