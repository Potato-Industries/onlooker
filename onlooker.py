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
  if DHCP in pkt and pkt[DHCP].options[0][1] == 1:
    for i in pkt[DHCP].options:
      if i[0] == "param_req_list":
        s["dhcp_fingerprint"] = ((str(i[1]).replace("[", "")).replace("]", "")).replace(", ", ",")
        continue
      if i[0] == "vendor_class_id":
        s["dhcp_vendor"] = i[1].decode()
        continue

    l["dhcp_request"] = pkt[Ether].src + " requesting a new ip"

  # OS - "DHCP Request - DHCP options"
  if DHCP in pkt and pkt[DHCP].options[0][1] == 3:
    for i in pkt[DHCP].options:
      if i[0] == "param_req_list":
        s["dhcp_fingerprint"] = ((str(i[1]).replace("[", "")).replace("]", "")).replace(", ", ",")
        continue
      if i[0] == "vendor_class_id":
        s["dhcp_vendor"] = i[1].decode()
        continue
      if i[0] == "requested_addr":
        l["dhcp_request"] = pkt[Ether].src + " requesting " + i[1]
        continue

  # OS - "UPNP USER-AGENT"
  if UDP in pkt and Raw in pkt:
    m = re.search(rb'USER-AGENT: (.*?)\r\n', pkt[Raw].load)
    try:
      s["upnp_user_agents"] = [m.group(1).decode()]
    except:
      pass

  # OS - "HTTP User-Agent"
  if TCP in pkt and Raw in pkt:
    m = re.search(rb'[Uu][Ss][Ee][Rr]-[Aa][Gg][Ee][Nn][Tt]: (.*?)\r\n', pkt[Raw].load)
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

  # TCP SYN Flags in p0f format

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
  sniff(iface="wlan0", filter="(udp) or (tcp and not src host 192.168.1.99)", prn=spotter)
