"""
Talks to the virustotal API and gets json back. Only implemented IP and domain look ups as those are within the scope.
"""

import urllib2
import urllib
import time

class VirusTotalQuery:

    def __init__(self, endpoint, apikey, reqLimit, reqTime):
        """
        :param endpoint: the api's endpoint
        :param apikey: the api key
        :param reqLimit: the maximum number of requests
        :param reqTime: the timeframe for reqLimit (in seconds)
        :return: creates an object that acts as interface to the api
        """
        self.endpoint = endpoint
        self.apikey = apikey
        self.reqLimit = reqLimit
        self.reqTime = reqTime

    def handleRequest(self, type, request):
        """
        :param type:  Type of request, can be IP, Domain or URL
        :param request: the content of the request (ip adres, domain or url)
        :return: JSON dict with the virustotal response
        """
        # dirty hack to sleep for 15 seconds to never exceed 4req/min limit.
        # this really should be handled more elegant eventually
        time.sleep(15)
        if type == 'url':
            type = 'resource'
            url = "url/report"
        elif type == 'ip':
            url = "ip-address/report"
        elif type == 'domain':
            url = "domain/report"

        parameters = {type: request, "apikey": self.apikey}
        response = urllib.urlopen('%s?%s' % (self.endpoint+url, urllib.urlencode(parameters)))
        json = response.read()
        return json






