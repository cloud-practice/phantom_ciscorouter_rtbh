#
"""
     module: cisco_csr_connector.py
     short_description: This Phantom app connects to the Cisco CSR platform
     author: Todd Ruch, World Wide Technology
     Revision history:
     25 Aug 2016  |  0.1 - stole base code from Joel
     21 April 2016  |  1.0 - initial release

     Copyright (c) 2016 World Wide Technology, Inc.

     This program is free software: you can redistribute it and/or modify
     it under the terms of the GNU Affero General Public License as published by
     the Free Software Foundation, either version 3 of the License, or
     (at your option) any later version.

     This program is distributed in the hope that it will be useful,
     but WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
     GNU Affero General Public License for more details.


"""
#
# Phantom App imports
#
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
#
#  system imports
#
import simplejson as json
import time
import requests
import httplib
import logging
import sys


# ========================================================
# AppConnector
# ========================================================


class CSR_Connector(BaseConnector):

    BANNER = "Cisco_CSR"

    def __init__(self):
        """
        Instance variables
        """
        # Call the BaseConnectors init first
        super(CSR_Connector, self).__init__()

        # standard port for IOS XE REST API
        self.REST_PORT = '55443'
        # base URI with version number
        self.BASE_URI = '/api/v1'
        # resourse URI
        self.RESOURCE = '/routing-svc/static-routes'
        # resource for auth token
        self.user = kwargs['user']
        self.TOKEN_RESOURCE = '/auth/token-services'
        self.headers
        self.HEADER = {"Content-Type": "application/json"}
        self.status_code = []

    def initialize(self):
        """
        This is an optional function that can be implemented by the AppConnector derived class. Since the configuration
        dictionary is already validated by the time this function is called, it's a good place to do any extra initialization
        of any internal modules. This function MUST return a value of either phantom.APP_SUCCESS or phantom.APP_ERROR.
        If this function returns phantom.APP_ERROR, then AppConnector::handle_action will not get called.
        """
        self.debug_print("%s INITIALIZE %s" % (CSR_Connector.BANNER, time.asctime()))
        return phantom.APP_SUCCESS

    def finalize(self):
        """
        This function gets called once all the param dictionary elements are looped over and no more handle_action calls
        are left to be made. It gives the AppConnector a chance to loop through all the results that were accumulated by
        multiple handle_action function calls and create any summary if required. Another usage is cleanup, disconnect
        from remote devices etc.
        """
        self.debug_print("%s FINALIZE Status: %s" % (CSR_Connector.BANNER, self.get_status()))
        return

    def handle_exception(self, exception_object):
        """
        All the code within BaseConnector::_handle_action is within a 'try: except:' clause. Thus if an exception occurs
        during the execution of this code it is caught at a single place. The resulting exception object is passed to the
        AppConnector::handle_exception() to do any cleanup of it's own if required. This exception is then added to the
        connector run result and passed back to spawn, which gets displayed in the Phantom UI.
        """
        self.debug_print("%s HANDLE_EXCEPTION %s" % (CSR_Connector.BANNER, exception_object))
        return


    def _test_connectivity(self, param):
        """
        Called when the user depresses the test connectivity button on the Phantom UI.
        Use a basic query of your organizations to determine if the authentication token is correct

        Meraki will send back a 3xx Redirect when you hit the first API. The requests module will
        handle the redirect for you, but it would be nice to know the actual server processing your
        request, so I will output the URL in the message.

            curl -X POST https://10.0.1.10:55443/api/v1/auth/token-services
                 -H "Accept:application/json" -u "{user}:{pass}" -d "" --insecure

        """
        self.debug_print("%s TEST_CONNECTIVITY %s" % (CSR_Connector.BANNER, param))
        self.user = param['user']
        self.password = param['password']
        response = get_token(self, self.user, self.password)
        return


    def listStaticBlackHoledIPs(self, param):
        """
            curl -k -X GET https://{trigger_rtr}:55443/api/v1/routing-svc/static-routes
                 -H "Accept:application/json" -u "{user}:{pass}"
                 -d '{"destination-network":"7.7.7.7/32","next-host-router":"192.0.2.1/32"}'
        """
        get_token(self, user, password)
        self.method = 'GET'
        result = self.run('get',TOKEN_RESOURCE)
        return


    def setStaticBlackHoledIP(self, param):
        """
            curl -k -X POST https://{trigger_rtr}:55443/api/v1/routing-svc/static-routes
                 -H "Accept:application/json" -u "{user}:{pass}"
                 -d '{"destination-network":"7.7.7.7/32","next-host-router":"192.0.2.1/32"}'
        """
        get_token(self, user, password)
        self.js = '{"destination-network":"7.7.7.7/32","next-host-router":"192.0.2.1/32"}'
        result = self.run('past',TOKEN_RESOURCE)
        return


    def delStaticBlackHoledIP(self, param):
        """
            curl -k -X DELETE https://{trigger_rtr}:55443/api/v1/routing-svc/static-routes
                 -H "Accept:application/json" -u "{user}:{pass}"
                 -d '{"destination-network":"7.7.7.7/32","next-host-router":"192.0.2.1/32"}'
        """
        resource = '/routing-svc/static-routes'
        get_token(self, user, password)
        self.js = '{"destination-network":"7.7.7.7/32","next-host-router":"192.0.2.1/32"}'
        result = self.run('delete',resource)
        return


    def get_token(self, user, password):
        """ get an auth token from the device """
        result = self.run('post',TOKEN_RESOURCE)
        self.token = result['token-id']
        logging.debug("token id: {0}".format(self.token))
        self.headers.update({'X-auth-token':self.token})
        logging.debug("{0}".format(result))
        return


    def build_url(self, rest_port=REST_PORT,resource=TOKEN_RESOURCE):
        """ build a URL for the REST resource """
        self.url = 'https://{0}:{1}{2}{3}'.format(self.device,self.port,self.version,resource)
        logging.debug('set full URL to: {0}'.format(self.url))
        return


    def run(self, method, resource):
        """ get/put/post/delete a request to the REST service """
        # a GET/POST/PUT/DELETE method name was passed in;
        # call the appropriate method from requests module
        request_method = getattr(requests,method)
        self.build_url(resource=resource)
        if self.json:
            self.headers.update({'Content-type':'application/json'})
            r = request_method(self.url, auth=(self.user,self.password),\
                    headers = self.headers,\
                    data = json.dumps(self.json),\
                    verify = False)
        else:
            r = request_method(self.url, auth=(self.user, self.password),\
                    headers = self.headers,\
                    verify = False)



    def api_action(self, URL):
        """ Method to query and return results, return an empty list if there are connection error(s).  """
        header = self.HEADER
        header["X-Cisco-Meraki-API-Key"] = self.get_configuration("Meraki-API-Key")
        URI = "https://" + self.get_configuration("dashboard") + URL
        try:
            r = requests.get(URI, headers=header, verify=False)
        except requests.ConnectionError as e:
            self.set_status_save_progress(phantom.APP_ERROR, str(e))
            return []
        self.status_code.append(r.status_code)

        try:
            return r.json()
        except ValueError:                                 # If you get a 404 error, throws a ValueError exception
            return []

    def handle_action(self, param):
        """
        This function implements the main functionality of the AppConnector. It gets called for every param dictionary element
        in the parameters array. In it's simplest form it gets the current action identifier and then calls a member function
        of it's own to handle the action. This function is expected to create the results of the action run that get added
        to the connector run. The return value of this function is mostly ignored by the BaseConnector. Instead it will
        just loop over the next param element in the parameters array and call handle_action again.

        We create a case structure in Python to allow for any number of actions to be easily added.
        """

        action_id = self.get_action_identifier()           # action_id determines what function to execute
        self.debug_print("%s HANDLE_ACTION action_id:%s parameters:\n%s" % (CSR_Connector.BANNER, action_id, param))

        supported_actions = {"test connectivity": self._test_connectivity,
                             "list black holes": self.listStaicBlackHoledIPs,
                             "create black hole": self.setStaticBlackHole,
                             "delete black hole": self.delStaticBlackHole}

        run_action = supported_actions[action_id]

        return run_action(param)


# =============================================================================================
# Logic for testing interactively e.g. python2.7 ./meraki_connector.py ./test_jsons/test.json
# If you don't reference your module with a "./" you will encounter a 'failed to load app json'
# =============================================================================================

if __name__ == '__main__':

    import sys

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:                           # input a json file that contains data like the configuration and action parameters,
        in_json = f.read()
        in_json = json.loads(in_json)
        print ("%s %s" % (sys.argv[1], json.dumps(in_json, indent=4)))

        connector = CSR_Connector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print ("%s %s" % (connector.BANNER, json.dumps(json.loads(ret_val), indent=4)))

    exit(0)
