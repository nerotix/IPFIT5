import dpkt
import redis
import socket
import struct
import json
from dpkt.udp import UDP
from pymongo import MongoClient

#own imports
import config

def int2ip(int_ip):
    return socket.inet_ntoa(struct.pack("!I", int_ip))

def main():
    # grabs the eth port to bind and the list of ignored domains from the config using the config.py module.
    eth = config.getSetting('setup', 'eth')
    ignoredDomains = config.getSetting('setup', 'ignore').split(',')
    s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.SOCK_DGRAM)
    s.bind((eth, 0x0800))


    global srcip, dnsnamen, dstip

    while True:
        # r_serv.flushall()
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

                createObj = response(dstip, srcip, dnsname)
                jsonwrap = json.dumps(createObj.__dict__)
                toRedis(jsonwrap)

idCounter = 0
def redisToMongo(pakket):
    global idCounter
    idCounter += 1
    # connectie aanmaken met mongodb
    client = MongoClient('localhost', 27017)
    # db selecteren van mongodb
    db = client.yapdns

    #h etgeen wat we naar mongodb willen schrijven
    pakketje = db.dnsinfo.insert_one(
        { "_id": idCounter, "dnspack": pakket}
    )

    # print alles wat er in de collectie dnsinfo staat in de mongodb
    dnspakketjes = db.dnsinfo.find({"_id": idCounter})
    for docs in dnspakketjes:
        print docs

def toRedis(pakket):
    #connectie opzetten voor redis
    r_serv = redis.StrictRedis(host='localhost', port=6379, db=0)

    # pushen van het object naar redis
    r_serv.rpush("dnsanswer", pakket)
    #print laatste dnsanswer in de list
    # return r_serv.lindex("dnsanswer", -1)
    redisToMongo(r_serv.lindex("dnsanswer", -1))

    # command voor het wipen van de redis database
    # r_serv.flushall()

# klasse die geinstantieerd wordt door de functie makeResponce
class response(object):

    def __init__(self, dstip, srcip, NA):
        self.dstip = dstip
        self.srcip = srcip
        self.NA = NA

    def __repr__(self):
        return "<%s %s %s>" % (self.dstip, self.srcip, self.NA)

if __name__ == '__main__':
    main()