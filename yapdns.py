import dpkt
import socket
import struct
import redis
from dpkt.udp import UDP

#own modules import after this
import config

r_serv = redis.StrictRedis(host='localhost', port=6379, db=0)

def int2ip(int_ip):
    return socket.inet_ntoa(struct.pack("!I", int_ip))


def main():
    # grabs the eth port to bind and the list of ignored domains from the config using the config.py module.
    eth = config.getSetting('setup', 'eth')
    ignoredDomains = config.getSetting('setup', 'ignore').split(',')
    s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.SOCK_DGRAM)
    s.bind((eth, 0x0800))

    global ipadr, dnsnamen

    while True:
        r_serv.flushall()
        data, addr = s.recvfrom(1024)
        eth = dpkt.ethernet.Ethernet(data)
        ip = eth.data
        if isinstance(ip, str):
            err_count += 1
            continue
        if type(ip.data) == UDP:
            udp = ip.data
            # print repr(udp)
            if udp.sport == 53:
                try:
                    dns = dpkt.dns.DNS(udp.data)
                    if dns.qr == 1:
                        for rr in dns.an:
                            if rr.type == 1:
                                #IP-adres
                                ipadr = int2ip(struct.unpack('>I', rr.rdata)[0])
                                # dst_ip_addr_str = socket.inet_ntoa(ip.dst)
                                # print dst_ip_addr_str
                            else:
                                # resource record
                                rtype = rr.type
                                print rtype

                except Exception as e:
                    raise e
                else:
                    #dns
                    dnsname = dns.qd[0].name
                makeResponse(ipadr, dnsname)

class response(object):
    IP = ""
    NA = ""

    def __init__(self, IP, NA):
        self.IP = IP
        self.NA = NA

    def __repr__(self):
        return "<%s %s>" % (self.IP, self.NA)

def makeResponse(IP, NA):
    Response = response(IP, NA)
    print Response
    return Response

if __name__ == '__main__':
    main()