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
import pymongo
import datetime
import hashlib
import logging
import sys


#   setup for logging, one log for the program and one for logging hashes as integrity check.
logFormatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
consoleFormatter = logging.Formatter('%(levelname)-8s %(message)s')
# The program logger, gets two handlers, one for console one for the file:
logger = logging.getLogger('logger')

# the file handler
fileHandler = logging.FileHandler('yapdns.log')
fileHandler.setFormatter(logFormatter)

# the console handler
console = logging.StreamHandler()
console.setFormatter(consoleFormatter)

# add both handlers to the logger
logger.addHandler(console)
logger.addHandler(fileHandler)

# set the level of logging to INFO
logger.setLevel(logging.INFO)

# integrity logger
integrityLogFormatter = logging.Formatter('%(message)s')
integrityLogger = logging.getLogger('record_integrity_logger')
integrityHandler = logging.FileHandler('recordIntegrity.log')
integrityHandler.setFormatter(integrityLogFormatter)
integrityLogger.addHandler(integrityHandler)
integrityLogger.setLevel(logging.INFO)

# connectie opzetten voor redis
r_serv = redis.StrictRedis(
    host=config.getSetting('redis', 'address'),
    port=config.getSetting('redis', 'port'),
    db=config.getSetting('redis', 'db'))

# test the reddis connection, log if needed.
try:
    response = r_serv.client_list()
    logger.info("Connected to redis")
except redis.ConnectionError:
    logger.critical("Failed to connect to redis")
    sys.exit()

# connectie opzetten voor mongo
MongoAddress = config.getSetting('mongo', 'address')
MongoPort = config.getSetting('mongo', 'port')
MongoUser = config.getSetting('mongo', 'user')
MongoPass = config.getSetting('mongo', 'password')
mongoTimeout = config.getSetting('mongo', 'timeout')

# test the mongo connection, kill the program if it fails
try:
    mongoClient = pymongo.MongoClient('mongodb://'+MongoUser+':' + MongoPass + '@' +MongoAddress+":"+MongoPort,
                                      serverSelectionTimeoutMS=mongoTimeout)
    mongoClient.server_info()
    logger.info("Connected to mongo")
except pymongo.errors.ServerSelectionTimeoutError as err:
    logger.critical("There is a problem with mongo: " + str(err))
    sys.exit()


def int2ip(int_ip):
    return socket.inet_ntoa(struct.pack("!I", int_ip))


def main():
    """
    This function will first call for the function to check the integrity of the db and hashes.
    Next it will assign the values that are found in the config file to the variable eth. Then
    it will start listening to UDP port 53 to catch all the traffic that arrives there. Next,
    it will filter out all the A records that are in the dns response and get the dns names
    that are connected to that A records. Lastly it will get the current system time and
    call for the function writes the data to redis.
    """
    checkIntegrity()
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
                except Exception:
                    continue
                else:
                    # dns
                    dnsname = dns.qd[0].name
                now = datetime.datetime.utcnow()
                ltime = now.strftime("%Y-%m-%dT%H:%M:%S") + ".%03d" % (now.microsecond / 1000) + "Z"
                toRedis(dstip, srcip, dnsname, ltime)

"""
This checks what the value is from the last stored records in MongoDB
if the dictionary contains more then 0 records, the teller will be the number
of the value stored at the key "_id". If the length of the dictionary is 0,
teller will be assigned the value of 0.
"""
db = mongoClient.yapdns
idList = list(db.dnsinfo.find({}, "_id"))
if idList.__len__() > 0:
    teller = int(idList[-1]['_id'])
else:
    teller = 0


def toRedis(dstip, srcip, dnsname, timestamp):
    """
    This function check whether the dns name is in the list ignoreDom,
    which is located in the config file. If the dnsname is in that list,
    the package is ignored. If it's not in that list, the package is handled.
    The teller will be upped by 1 every time the package is handled and
    it will created 3 threads, vtThread will start the VTHandler function, the
    fsThread will start the FSHandler function and both will then write it's data
    to the Redis server. The  awThread will gives the value's of the other 2
    threads and the teller to a new thread that watches whether the running threads
    are done.
    :param dstip: destination to where the dns package is going to
    :param srcip: IP-address from where the dns package originated
    :param name: dns name from the dns package response
    :param timestamp: current system time
    """
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

        #print r_serv.hgetall("_id" + str(teller))

ipTeller = 0

def hasher(record):
    tohash = record['_id'] + record['source'] + record['destination'] + record['timestamp']
    hash_object = hashlib.md5(tohash)
    hash = hash_object.hexdigest()
    integrityLogger.info("ID: " + record["_id"] + " MD5: " + hash)


def checkIntegrity():
    with open('recordIntegrity.log') as f:
        for line in f:
            list = line.split()
            id = list[1]
            md5 = list[3]
            db = mongoClient.yapdns
            record = db.dnsinfo.find_one({"_id":id})
            #build something to base the hash on
            tohash = record['_id'] + record['source'] + record['destination'] + record['timestamp']
            hash_object = hashlib.md5(tohash)
            hash = hash_object.hexdigest()
            if hash == md5:
                print id+ " checks out"
            else:
                print id + " does not check out"


def apiWatcher(vtThread, fsThread, id):
    """
    This function will wait until both the threads are finished, once
    the threads are finished, it will start the function toMongo with
    the value from id.
    :param vtThread: thread that handles the responses from VirusTotal
    :param fsThread: thread that handles the responses from Farsight
    :param id: value of teller from the function toRedis
    """
    vtThread.join()
    fsThread.join()
    toMongo(id)


def FSHandler(srcip):
    """
    This function creates an object from the farsight script with the values
    that are found in the config file. After the object is created, the object
    does a request with the param to the farsight database. Next, it checks how
    many company's are attached to 1 IP-address, if that is more than 5, it will
    send the value "FastFlux" to the Redis database, else it will send the value
    "Clean" to the database.
    :param srcip: IP-address from where the dns package came from
    """
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
    """
    This function create an object of the VirusTotal script with the values
    that are found in the config file. After the object is created, the object
    does a request with the param. Lastly it checks what the value is of the
    positives hits in the answer.
    :param name: name from dns package
    :return: value based on the number of hits that VirusTotal gives
    """
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
            return 0
    else:
        return 0


def toMongo(id):
    """
    This function is called when both threads are finished. Then it will
    create a variable records that contains all the information stored
    in Redis with a certain id. Next it will insert the value to MongoDB.
    Lastly it will give the value of record to the function hasher.
    :param id: id has the value from teller in the function toRedis
    """
    record = r_serv.hgetall("_id" + str(id))
    db.dnsinfo.insert_one(record)
    # build something to base the hash on
    hasher(record)


if __name__ == '__main__':
    main()
