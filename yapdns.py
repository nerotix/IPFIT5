import dpkt
import socket
import struct
import redis
from dpkt.udp import UDP

r_serv = redis.StrictRedis(host='localhost', port=6379, db=0)

def int2ip(int_ip):
    return socket.inet_ntoa(struct.pack("!I", int_ip))


def main():
    s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.SOCK_DGRAM)
    s.bind(('ens33', 0x0800))

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
                        srcip = socket.inet_ntoa(ip.dst)
                        for answer in dns.an:
                            if answer.type == 1:
                                # IP-adres
                                ipadr = int2ip(struct.unpack('>I', answer.rdata)[0])
                            else:
                                # resource record
                                # rtype = rr.type
                                # print rtype
                                continue
                except Exception as e:
                    raise e
                else:
                    # dns
                    # dnsname = dns.qd[0].name
                    for qname in dns.qd:
                        print qname.name
                # makeResponse(srcip, ipadr, dnsname)

class response(object):
    SIP = ""
    DIP = ""
    NA = ""

    def __init__(self, SIP, DIP, NA):
        self.SIP = SIP
        self.DIP = DIP
        self.NA = NA

    def __repr__(self):
        return "<%s %s %s>" % (self.SIP, self.DIP, self.NA)

def makeResponse(SIP, DIP, NA):
    Response = response(SIP, DIP, NA)
    print Response
    return Response

if __name__ == '__main__':
    main()