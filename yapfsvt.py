import dpkt
import redis
import socket
import struct
import time
import json
import threading
import pygeoip
import dnsdb_query as fsReq
import virustotal_query as vtReq
from dpkt.udp import UDP
from pymongo import MongoClient

#own imports
import config

# connectie opzetten voor redis
r_serv = redis.StrictRedis(host='localhost', port=6379, db=0)

def int2ip(int_ip):
    return socket.inet_ntoa(struct.pack("!I", int_ip))

def main():
    # grabs the eth port to bind and the list of ignored domains from the config using the config.py module.
    eth = config.getSetting('setup', 'eth')
    # ignoredDomains = config.getSetting('setup', 'ignore').split(',')
    s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.SOCK_DGRAM)
    s.bind((eth, 0x0800))

    global srcip, dnsnamen, dstip

    while True:
        data, addr = s.recvfrom(1024)
        eth = dpkt.ethernet.Ethernet(data)
        ip = eth.data
        if isinstance(ip, str):
            # err_count += 1
            continue
        if type(ip.data) == UDP:
            udp = ip.data
            # print repr(udp)
            if udp.sport == 53:
                try:
                    dns = dpkt.dns.DNS(udp.data)
                    if dns.qr == 1:
                        # destination ip van het pakketje
                        dstip = socket.inet_ntoa(ip.dst)
                        for answer in dns.an:
                            if answer.type == 1:
                                # source ip van het pakketje
                                srcip = int2ip(struct.unpack('>I', answer.rdata)[0])
                            else:
                                # resource record
                                # rtype = rr.type
                                # print rtype
                                continue
                except Exception as e:
                    #print e
                    continue
                else:
                    # dns
                    dnsname = dns.qd[0].name

                # createObj = response(dstip, srcip, dnsname)
                # jsonwrap = json.dumps(createObj.__dict__)
                # toRedis(jsonwrap)
                toRedis(dstip, srcip, dnsname)

teller = 0
def toRedis(dstip, srcip, dnsname):
    global teller

    ignoreDom = config.getSetting('setup', 'ignore')

    if dnsname in ignoreDom:
        pass
    else:
        teller += 1
        answer = {"_id": teller, "destination": dstip, "source": srcip, "name": dnsname}
        r_serv.hmset("_id" + str(teller), answer)

        vtThread = threading.Thread(target=r_serv.hset, args=("_id" + str(teller),
                           "vt", VTHandler(r_serv.hget("_id" + str(teller), "source"))))
        vtThread.start()

        # haalt info vanuit farsight op
        try:
            fsThread = threading.Thread(target=FSHandler(r_serv.hget("_id" + str(teller), "source")))
            fsThread.start()
        except Exception:
            pass
        # time.sleep(0.5)
        # print r_serv.hgetall("_id" + str(teller))

ipTeller = 0
def FSHandler(srcip):
    global ipTeller

    request = fsReq.DnsdbClient(
        server=config.getSetting("dnsdb", "endpoint"),
        apikey=config.getSetting("dnsdb", "key")
    )

    geo = pygeoip.GeoIP("GeoIPASNum.dat")
    ipTeller += 1
    for rrset in request.query_rdata_ip(srcip):
        fsinfo = rrset.get("rdata")
        answer = {"_id": ipTeller, "IP": fsinfo}

        if r_serv.hget("ipID" + str(ipTeller), "IP") == fsinfo:
            pass
        else:
            r_serv.hmset("ipID" + str(ipTeller), answer)
            # print r_serv.hget("ipID" + str(ipTeller), "IP")
            asnInfo = geo.org_by_addr(r_serv.hget("ipID" + str(ipTeller), "IP"))
            r_serv.hset("asnID" + str(ipTeller), "ASN", asnInfo)
            print r_serv.hget("asnID" + str(ipTeller), "ASN")
            print len(r_serv.hgetall("asnID" + str(ipTeller)))

def VTHandler(srcip):

    request = vtReq.VirusTotalQuery(
        endpoint=config.getSetting("virustotal", "endpoint"),
        apikey=config.getSetting("virustotal", "key"),
        reqLimit=config.getSetting("virustotal", "reqLimit"),
        reqTime=config.getSetting("virustotal", "reqTimeframe")
    )

    return request.handleRequest("url", srcip)

# klasse voor het maken van een object
class response(object):

    def __init__(self, dstip, srcip, NA, FAR, VT):
        self.dstip = dstip
        self.srcip = srcip
        self.NA = NA
        self.FAR = FAR
        self.VT = VT

    def __repr__(self):
        return "<%s %s %s>" % (self.dstip, self.srcip, self.NA, self.FAR, self.VT)

if __name__ == '__main__':
    main()