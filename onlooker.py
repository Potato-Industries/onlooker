from scapy.all import *
import http.client
import json

load_module("p0f")

# update api key!
API = "aBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaB"

def fingerbankAPI(sig):
  url = "/api/v2/combinations/interrogate?key=" + API
  c = http.client.HTTPSConnection("api.fingerbank.org")
  param = json.dumps(sig)
  print ("Querying api.fingerbank.org..")
  print (" * OS signature: " + str(param))
  header = {"Content-type": "application/json"}
  c.request("POST", url, param, header)
  r = c.getresponse()
  print (r.status, r.reason)
  data = json.loads(r.read())
  c.close()
  print (json.dumps(data, indent=2, sort_keys=False))

def spotter(pkt):
  s = {}
  l = {}

  # OS - "DHCP Discover - DHCP options"
  if DHCP in pkt and pkt[DHCP].options[0][1] == 1 and type(pkt[DHCP].options[2][1]) == list:
    s["dhcp_fingerprint"] = ((str(pkt[DHCP].options[2][1]).replace("[", "")).replace("]", "")).replace(", ", ",")
    l["dhcp_request"] = pkt[Ether].src + " requesting ip"
    l["dhcp_hostname"] = pkt[DHCP].options[1][1]

  # OS - "DHCP Request - DHCP options"
  if DHCP in pkt and pkt[DHCP].options[0][1] == 3 and type(pkt[DHCP].options[3][1]) == list:
    s["dhcp_fingerprint"] = ((str(pkt[DHCP].options[3][1]).replace("[", "")).replace("]", "")).replace(", ", ",")
    l["dhcp_request"] = pkt[Ether].src + " requesting " + pkt[DHCP].options[2][1]
    l["dhcp_hostname"] = pkt[DHCP].options[1][1]

  # OS - "UDP/TCP User-Agent"
  if Raw in pkt:
    m = re.search(rb'[uU][sS][eE][rR]-[aA][gG][eE][nN][tT]: (.*?)\r\n', pkt[Raw].load)
    try:
      s["user_agents"] = [m.group(1).decode()]
    except:
      pass

  # UDP
  if UDP in pkt:
    l["udp_src_dst"] = str(pkt[UDP].sport) + " -> " + str(pkt[UDP].dport)

  # TCP
  if TCP in pkt:
    l["tcp_src_dst"] = str(pkt[TCP].sport) + " -> " + str(pkt[TCP].dport)
    l["tcp_window_size"] = pkt[TCP].window

  # IP
  if IP in pkt:
    l["ip_src_dst"] = pkt[IP].src + " -> " + pkt[IP].dst
    l["ip_ttl"] = pkt[IP].ttl

  # OS - "MAC"
  if Ether in pkt:
    s["mac"] = str(pkt[Ether].src).replace(":", "")
    l["mac_src_dst"] = pkt[Ether].src + " -> " + pkt[Ether].dst
    l["p0f"] = prnp0f(pkt)

  if len(l) > 1 and (l["p0f"] != None or len(s) > 1):
    print ("\nHost detected..")
    for i in l:
      print (" * " + str(i) + " | " + str(l[i]))
    print ("")

  if len(s) > 1:
    fingerbankAPI(s)

if __name__ == "__main__":
  print ("onlooker v0.1 - passive OS detection using Fingerbank API.")
  print (" * listening..")
  # update src ip!
  sniff(filter="(udp) or (tcp and not src host 192.168.1.100)", prn=spotter)
