import json
import logging
import sys

# standard port for IOS XE REST API
REST_PORT = '55443'
# base URI with version number
BASE_URI = '/api/v1'
# resourse URI
RESOURCE = '/routing-svc/static-routes'
# resource for auth token
TOKEN_RESOURCE = '/auth/token-services'
ACCEPT_HEADERS = {'Accept':'application/json'}

class RestClassCSR( user, password, device ):
    """
    SBRTBH (source based remote triggered black hole) CSR1000v REST API
    """
    def __init__(self,**kwargs):
        self.version = BASE_URI
        self.TOKEN_RESOURCE = TOKEN_RESOURCE
        self.headers = ACCEPT_HEADERS
        self.user = kwargs['user']
        self.password = kwargs['password']
        self.device = kwargs['device']
        self.port = REST_PORT
        self.json = ''

    def get_token(self):
        """ get an auth token from the device """
        r = self.run('post',TOKEN_RESOURCE)
        self.token = r['token-id']
        logging.debug('got session token: %s' % self.token)
        self.session_link = r['link']
        logging.debug('got session link: %s' % self.session_link)
        self.headers.update({'X-auth-token':self.token})
        return 

    def set_json(self,js):
        """ set JSON dict for use in request """
        self.json = js
        logging.debug('setting JSON dict:' % js)
        return

    def generate_url(self,rest_port=REST_PORT,resource=TOKEN_RESOURCE):
        """ build a URL for the REST resource """
        self.url = 'https://%s:%s%s%s' % (self.device,self.port,self.version,resource)
        logging.debug('set full URL to: %s' % self.url)
        return 

    def getStaticRoutes():
        result = 


    def addBlackHoledIP():
        pass


    def removeBlackHoledIP():
        pass

if __name__ == '__main__':

    testharness()
