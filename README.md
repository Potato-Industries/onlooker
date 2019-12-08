# onlooker

passive os detection using Fingerbank API

- https://fingerbank.org/
- https://scapy.net/

**Usage**

requires a Fingerbank api key (https://fingerbank.org/usage/#/usage) 

```
root@kali:/opt/onlooker# python3 onlooker.py 
onlooker v0.1 - passive OS detection using Fingerbank API.
 * listening..

Host detected..
 * udp_src_dst | 68 -> 67
 * p0f | None
 * dhcp_hostname | openbsd65
 * ip_src_dst | 0.0.0.0 -> 255.255.255.255
 * dhcp_request | 80:90:c1:d0:80:90 requesting ip
 * ip_ttl | 128
 * mac_src_dst | 80:90:c1:d0:80:90 -> ff:ff:ff:ff:ff:ff

Querying api.fingerbank.org..
 * OS signature: {"mac": "8090c1d08090", "dhcp_fingerprint": "1,28,2,121,3,15,119,6,12,67,66"}
200 OK
{
  "device": {
    "can_be_more_precise": false, 
    "name": "OpenBSD", 
    "created_at": "2014-09-09T15:09:52.000Z", 
    "updated_at": "2014-09-09T15:09:55.000Z", 
    "virtual_parent_id": null, 
    "parent_id": 14, 
    "parents": [
      {
        "name": "BSD OS"
```
Enjoy~
