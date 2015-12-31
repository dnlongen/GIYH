import base64
from scapy.all import rdpcap

# Read in the pcap, then use scapy to sort packets by time
p=rdpcap("giyh-capture.pcap")
o=sorted(p, key=lambda ts: ts.time)

# Visual scan of wireshark shows data I'm interested in is packets 877 to 1403
# With these packets, if a DNS record sent to 52.2.229.189, pull data from rdata field
# rdata has length encoded in the first position, so use offset 1, then base64 decode it
# decoded data begins with "FILE:" in each record, so grab everything from offset 5 to end
# Append all into one byte-string, then write out to a file

y= ""
for num in range(876, 1403):
  if hasattr(o[num], "dst") and o[num].dst=="52.2.229.189" and hasattr(o[num], "an"): y += base64.b64decode(o[num].an.rdata[1:])[5:]

jpg=open("snapshot_CURRENT.jpg",'wb')
jpg.write(y)
jpg.close()
