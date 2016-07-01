import dpkt
import redis
import socket
import struct
import config
import time
import json
import threading
import pygeoip
import dnsdb_query as fsReq
import virustotal_query as vtReq
from dpkt.udp import UDP
from pymongo import MongoClient
import datetime
import hashlib
import logging

#   setup for logging
logging.basicConfig(filename='recordIntegrity.log', format='%(message)s', level=logging.DEBUG)


# connectie opzetten voor redis
r_serv = redis.StrictRedis(
    host=config.getSetting('redis', 'address'),
    port=config.getSetting('redis', 'port'),
    db=config.getSetting('redis', 'db'))

# connectie opzetten voor mongo
MongoAddress = config.getSetting('mongo', 'address')
MongoPort = config.getSetting('mongo', 'port')
MongoUser = config.getSetting('mongo', 'user')
MongoPass = config.getSetting('mongo', 'password')
mongoClient = MongoClient('mongodb://'+MongoUser+':' + MongoPass + '@' +MongoAddress+":"+MongoPort)


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
            continue
        if type(ip.data) == UDP:
            udp = ip.data
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
                                continue
                except Exception as e:
                    #print e
                    continue
                else:
                    # dns
                    dnsname = dns.qd[0].name
                now = datetime.datetime.utcnow()
                ltime = now.strftime("%Y-%m-%dT%H:%M:%S") + ".%03d" % (now.microsecond / 1000) + "Z"
                toRedis(dstip, srcip, dnsname, ltime)

teller = 0


def toRedis(dstip, srcip, dnsname, timestamp):
    global teller

    ignoreDom = config.getSetting('setup', 'ignore')

    if dnsname in ignoreDom:
        pass
    else:
        teller += 1
        answer = {"_id": teller, "destination": dstip, "source": srcip, "name": dnsname, "timestamp": timestamp}
        r_serv.hmset("_id" + str(teller), answer)

        vtThread = threading.Thread(target=r_serv.hset, args=("_id" + str(teller),
                           "vt", VTHandler(r_serv.hget("_id" + str(teller), "name"))))
        vtThread.start()

        # haalt info vanuit farsight op, moet mogelijk in try/except block?
        fsThread = threading.Thread(target=FSHandler, args=(answer["source"],))
        fsThread.start()

        awThread = threading.Thread(target=apiWatcher, args=(vtThread, fsThread,  teller))
        awThread.start()

        print r_serv.hgetall("_id" + str(teller))

ipTeller = 0

def hasher(record):
    hash_object = hashlib.md5(repr(record))
    hash = hash_object.hexdigest()
    #print "ID: " + record["_id"] + " hash: " + hash
    logging.info("ID: " + record["_id"] + " MD5: " + hash)


def apiWatcher(vtThread, fsThread, id):
    vtThread.join()
    fsThread.join()
    toMongo(id)
    #print "ik heb iets naar mongo geschreven"


def FSHandler(srcip):
    global ipTeller

    request = fsReq.DnsdbClient(
        server=config.getSetting("dnsdb", "endpoint"),
        apikey=config.getSetting("dnsdb", "key")
    )

    geo = pygeoip.GeoIP("GeoIPASNum.dat")
    ipTeller += 1
    try:
        for rrset in request.query_rdata_ip(srcip):
            fsinfo = rrset.get("rdata")
            answer = {"_id": ipTeller, "IP": fsinfo}

            if r_serv.hget("ipID" + str(ipTeller), "IP") == fsinfo:
                pass
            else:
                r_serv.hmset("ipID" + str(ipTeller), answer)
                asnInfo = geo.org_by_addr(r_serv.hget("ipID" + str(ipTeller), "IP"))
                r_serv.hset("asnID" + str(ipTeller), "ASN", asnInfo)
                if len(r_serv.hgetall("asnID" + str(ipTeller))) >= 5:
                    r_serv.hset("_id" + str(teller), "fs", "FastFlux")
                else:
                    r_serv.hset("_id" + str(teller), "fs", "Clean")
    except Exception:
        pass


def VTHandler(name):

    request = vtReq.VirusTotalQuery(
        endpoint=config.getSetting("virustotal", "endpoint"),
        apikey=config.getSetting("virustotal", "key"),
        reqLimit=config.getSetting("virustotal", "reqLimit"),
        reqTime=config.getSetting("virustotal", "reqTimeframe")
    )

    vtPos = request.handleRequest("url", name)
    respCode = json.loads(vtPos)['response_code']
    if respCode == 1:
        posHits = json.loads(vtPos)['positives']
        if posHits >= 1:
            return int((json.loads(vtPos)['positives']))
        else:
            return "No hits!"
    else:
        return "IP Not found in DB."


def toMongo(id):
    db = mongoClient.yapdns
    db.dnsinfo.insert_one(
       r_serv.hgetall("_id" + str(id))
    )

    hasher(
        r_serv.hgetall("_id" + str(id))
    )


if __name__ == '__main__':
    main()
