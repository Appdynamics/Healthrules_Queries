#
# Maintainer: David Ryder, David.Ryder@AppDynamics.com
#
# Fetches, Loads, rewrites AppDynamics Health Rules and Analytics Search Queries from a rules file
# Allows one to many rules to be created from a base template against a rules file
# Automatic creation of Analytics Search Queries from
#
#
import os
import sys
import requests
import datetime
import json
import xml.etree.ElementTree as xmlet
import csv
import uuid

class APPD():
    def __init__(self, show=False):
        self.show = show
        self.auth = ""
        self.applications = ""
        self.analyicsMetrics = {}
        self.appIds = {}
        self.nodes = ""

    def print(self):
        print( self.auth )

    def httpURL(self, path):
        return "{0}://{1}:{2}{3}".format(self.auth['HTTP_PROTOCOL'],self.auth['APPDYNAMICS_CONTROLLER_HOST_NAME'], self.auth['APPDYNAMICS_CONTROLLER_PORT'], path)

    def httpHeaders(self):
        return { "Authorization": "Bearer " + self.auth['access_token'] }

    def httpHeaders2(self):
        return { "Accept": "application/json, text/plain, */*",
                 "Accept-Encoding": "gzip, deflate",
                 "Accept-Language": "en-US,en;q=0.9",
                 "Connection": "keep-alive",
                 "Content-Type": "application/json;charset=utf-8",
                 "Origin": self.httpURL(""),
                 "Referer": self.httpURL("/controller/") }

    def configure(self):
        # configure from ennvars
        requiredEnvvars = [ "APPD_CONTROLLER_ADMIN", "APPDYNAMICS_AGENT_ACCOUNT_NAME", "APPD_UNIVERSAL_PWD", "APPD_API_CLIENT_NAME",
                            "APPD_API_CLIENT_SECRET", "APPDYNAMICS_CONTROLLER_HOST_NAME", "APPDYNAMICS_CONTROLLER_PORT",
                            "APPDYNAMICS_CONTROLLER_SSL_ENABLED", "APPD_CONFIG_DIR" ]
        try:
            self.auth = { v: os.environ[ v ] for v in requiredEnvvars }
            self.auth.update( {'access_token': "", 'expires_in': "", 'session': "",
                               'HTTP_PROTOCOL': 'HTTPS' if self.auth['APPDYNAMICS_CONTROLLER_SSL_ENABLED'].lower() == 'true' else 'HTTP' } )
        except Exception as e:
            print( "Environment variable missing: {0}".format(e) )
            sys.exit()
            raise Exception( "Environment variable missing: {0}".format(e) )

    def configureBasic(self):
        # configure from ennvars
        print( "Configure Basic" )
        requiredEnvvars = [ "APPD_CONTROLLER_ADMIN", "APPD_UNIVERSAL_PWD", "APPDYNAMICS_CONTROLLER_HOST_NAME", "APPDYNAMICS_CONTROLLER_PORT",
                            "APPDYNAMICS_CONTROLLER_SSL_ENABLED", "APPDYNAMICS_AGENT_ACCOUNT_NAME" ]
        try:
            self.auth = { v: os.environ[ v ] for v in requiredEnvvars }
            self.auth.update( {'access_token': "", 'expires_in': "", 'session': "",
                               'HTTP_PROTOCOL': 'HTTPS' if self.auth['APPDYNAMICS_CONTROLLER_SSL_ENABLED'].lower() == 'true' else 'HTTP' } )
        except Exception as e:
            print( "Environment variable missing: {0}".format(e) )
            sys.exit()
            #raise Exception( "Environment variable missing: {0}".format(e) )

    def authenticateOauth(self):
        s = requests.session()
        r = s.post(self.httpURL("/api/oauth/access_token"),
                                auth=("{0}@{1}".format(self.auth['APPD_CONTROLLER_ADMIN'], self.auth['APPDYNAMICS_AGENT_ACCOUNT_NAME']), "{0}".format( self.auth['APPD_UNIVERSAL_PWD'] ) ),
                                headers={"Content-Type": "application/vnd.appd.cntrl+protobuf;v=1" },
                                data={"grant_type": "client_credentials",
                                      "client_id": self.auth['APPD_API_CLIENT_NAME']+"@"+self.auth['APPDYNAMICS_AGENT_ACCOUNT_NAME'],
                                      "client_secret": self.auth['APPD_API_CLIENT_SECRET'] } )
        if r.status_code != requests.codes.ok:
            print("Authentication error: status_code: {0}, [{1}]".format(r.status_code, r.text ))
            raise Exception( "Authentication error: status_code: {0}".format(r.status_code) )
        else:
            self.auth.update({'access_token': r.json()['access_token'], 'expires_in': r.json()['expires_in'], 'session': s})
            self.auth['session'].headers.update(self.httpHeaders())

    def authenticateBasic(self):
        self.auth.update( { 'session': requests.Session() } )
        r = self.auth['session'].get(self.httpURL("/controller/auth?action=login"),
                                     auth=("{0}@{1}".format(self.auth['APPD_CONTROLLER_ADMIN'],
                                     self.auth['APPDYNAMICS_AGENT_ACCOUNT_NAME']), "{0}".format( self.auth['APPD_UNIVERSAL_PWD'] )))
        if r.status_code != 200:
            print("Authentication error: status_code: {0}, {1}".format(r.status_code,r.text ))
            raise Exception( "Authentication error: status_code: {0}".format(r.status_code) )
        else:
            cookies = self.auth['session'].cookies.get_dict()
            self.auth['session'].headers.update({"X-CSRF-TOKEN": cookies['X-CSRF-TOKEN'] })
            self.auth['session'].headers.update(self.httpHeaders2())
            self.auth.update( {'access_token': None, 'expires_in': None,
                               'Expires': r.headers['Expires'],
                               'headers': self.auth['session'].headers,
                               'Set-Cookie': r.headers['Set-Cookie'] } )


    def getApplications(self):
        r = self.auth['session'].get(self.httpURL("/controller/rest/applications?output=json"), headers=self.auth['session'].headers )
        if r.status_code != 200:
            print("Authentication error ", r.status_code)
            print( r.text )
        else:
            #auth.update( {'applications': r.json()} )
            self.applications = r.json()

    def getNodes(self, appId):
        r = self.auth['session'].get(self.httpURL("/controller/rest/applications/{0}/nodes?output=json".format(appId)),
                headers=self.httpHeaders() )
        if r.status_code != 200:
            print("Authentication error ", r.status_code)
            print( r.text )
        else:
            self.nodes = r.json()
            print( r.json() )

    def getAppIdFromApplications(self, appName):
        # get app id from applications
        try:
            appId = [ i  for i in self.applications if i['name'] == appName ][0]['id']
        except Exception as e:
            appId = 0
        return appId

    def getAppId(self, appName):
        # get app id from self.appIds
        if appName in self.appIds.keys():
            appId = self.appIds[appName]
        else:
            appId = 0
            print( "Unknown application {0}".format(appName))
            raise Exception( "Unknown application {0}".format(appName) )
        return appId

    def getHealthRule(self, appId, healthRuleName):
        r = self.auth['session'].get(self.httpURL("/controller/healthrules/{0}?name={1}".format(appId, healthRuleName)), headers=self.httpHeaders())
        if r.status_code != 200:
            print("Authentication error ", r.status_code)
        return r.text

    def putHealthRule(self, appId, healthRuleXML):
        r = self.auth['session'].post(self.httpURL("/controller/healthrules/{0}".format(appId)),
                headers=self.httpHeaders(), files={ "file": healthRuleXML } )
        print( r.text )
        if r.status_code != 200:
            print("Error ", r.status_code)
            print( r.text )

    def testHealthRule(self, appId):
        # http://drydersys5apps-drydertest1-hrta3wjj.srv.ravcloud.com:8090/controller/restui/healthRules/getHealthRuleCurrentEvaluationStatus/app/5/healthRuleID
        # http://drydersys5apps-drydertest1-hrta3wjj.srv.ravcloud.com:8090/controller/restui/healthRules/getHealthRuleCurrentEvaluationStatus/app/5/healthRuleID/107
        # http://drydersys5apps-drydertest1-hrta3wjj.srv.ravcloud.com:8090/controller/restui/healthRules/getHealthRuleEvaluationEvents
        # http://drydersys5apps-drydertest1-hrta3wjj.srv.ravcloud.com:8090/controller/restui/healthRules/delete

        r = self.auth['session'].get(self.httpURL("/controller/restui/healthrules/getHealthRuleCurrentEvaluationStatus/app/{0}/healthRuleID/".format(appId)),
                headers=self.httpHeaders() )
        print( r.text )
        if r.status_code != 200:
            print("Error ", r.status_code)
            print( r.text )

    def putHealthRuleFromFile(self, appId, healthRuleFile, overWrite=False):
        overWriteStr = "true" if overWrite else "false"
        with open(healthRuleFile, 'r') as f1:
            healthRuleXML = f1.read()
            r = self.auth['session'].post(self.httpURL("/controller/healthrules/{0}?overwrite={1}".format(appId, overWriteStr)),
                    headers=self.httpHeaders(), files={ "file": healthRuleXML } )
            print( r.text )
            if r.status_code != 200:
                print("Error ", r.status_code)
                print( r.text )

    def xmlAddParent(self, hr1):
        hr2 = xmlet.Element('health-rules')
        hr2.insert(1,hr1)
        return hr2


    def getHealthRulesNew(self, appName):
        appId = self.getAppId( appName )

    def getAllHealhRules(self, appName):
        appId = self.getAppId( appName )
        if appId > 0:
            r = self.auth['session'].get(self.httpURL("/controller/healthrules/{0}".format(appId)), headers=self.httpHeaders())
            if r.status_code != 200:
                print("Authentication error ", r.status_code)
            else:
                #d1 = os.path.join(self.auth["APPD_CONFIG_DIR"], appName, "healhrules", "all.xml" )
                #print( "Writing to {0}".format(d1) )
                #with open(d1, 'w') as f1:
                #    f1.write( r.text )
                r = xmlet.fromstring( r.text )
                #r = t.getroot() # no root using fromstring
                print( r.tag )
                for hr in r.findall(".//health-rule"):
                    hrName = hr.find('name').text
                    print( "Health-rule: {0}".format(hrName))
                    hr2 = self.xmlAddParent(hr) # Add parent <health-rules>
                    hrXML = xmlet.tostring(hr2, encoding='us-ascii', method='xml')
                    d1 = os.path.join(self.auth["APPD_CONFIG_DIR"], appName, "healthrules", hrName + ".xml" )
                    with open(d1, 'w') as f1:
                        f1.write( hrXML.decode() )

    def loadHealthRuleFromFile(self, appName, hrXMLFile, overWrite=False):
        appId = self.getAppId( appName )
        fn = os.path.join(self.auth["APPD_CONFIG_DIR"], appName, "healthrules", hrXMLFile)
        if fn.endswith(".xml"):
            if os.path.exists( fn ):
                print( "Loading {0}".format(fn))
                self.putHealthRuleFromFile( appId, fn, overWrite )
            else:
                print( "Healthrule file does not exist {0}".format(fn) )
        else:
            print( "Ignoring ", fn )

    def loadAllHealthRulesFromDir(self, appName, overWrite=False):
        # Loads every rule in the config dir for the app
        d1 = os.path.join(self.auth["APPD_CONFIG_DIR"], appName, "healthrules")
        for fn in os.listdir(d1):
            if fn.endswith(".xml"):
                self.loadHealthRuleFromFile( appName, fn )
            else:
                print( "Ignoring ", fn )

    def healthruleStructure(self, appName, hrName):
        # TBD
        fn = os.path.join(self.auth["APPD_CONFIG_DIR"], appName, "healthrules", hrName + ".xml")
        if fn.endswith(".xml"):
            if os.path.exists( fn ):
                print( "Opening {0}".format(fn))
                r = xmlet.parse( fn )
                root = r.getroot()
                for elem in root.iter():
                    print("X ", elem.tag, elem.text)

                #self.linearize(root, "prefix" + "//" + self.removeNS(root.tag))
                print( "HR NAME ", r.find('.//health-rule/name').text)
            else:
                print( "Healthrule file does not exist {0}".format(fn) )
        else:
            print( "Ignoring ", fn )

    def getAllAppIDs(self):
        # Ref: https://appdynamics.zendesk.com/agent/tickets/52616
        r = self.auth['session'].get(self.httpURL("/controller/restui/applicationManagerUiBean/getApplicationsAllTypes?output=json"),
                                     headers=self.auth['session'].headers )
        if r.status_code != 200:
            print("Authentication error ", r.status_code)
            #print( r.text )
        else:
            applications = ['apmApplications', 'eumWebApplications', 'dbMonApplication', 'simApplication', 'analyticsApplication', 'mobileAppContainers', 'iotApplications']
            # Only getting: analyticsApplication, apmApplications
            self.analyticsApplicationId = r.json()['analyticsApplication']['id']
            self.appIds.update( { 'analyticsApplication': r.json()['analyticsApplication']['id']  } )
            self.appIds.update( { i['name']: i['id'] for i in r.json()['apmApplications'] } )

            #for i in r.json()['apmApplications']:
            #    self.appIds.update( { i['name']: i['id'] } )

    def printAppIDs(self):
        for i in self.appIds.items():
            print( "{0} {1}".format(i[0], i[1]))

    def createConfigDir(self):
        # top level APPD_CONFIG_DIR -> application_name -> healhrules
        # os.path.join(os.getcwd()),
        configDirList = ["healthrules", "business-transactions", "configuration", "dashboards"]
        configDir = self.auth["APPD_CONFIG_DIR"]
        print( configDir,configDirList )
        if os.path.exists( configDir ):
            print( self.appIds.items() )
            for i in self.appIds.items():
                for dirName in configDirList:
                    d1 = os.path.join(configDir, i[0], dirName )
                    print( d1 )
                    if not os.path.exists( d1 ):
                        os.makedirs(d1)
        else:
            print("Configuration dir {0} does not exist".format(configDir))

    def createHealthRules(self, rulesFile, appName, templateHrName):
        # Overwrite healhrule using template
        fn = os.path.join(self.auth["APPD_CONFIG_DIR"], appName, "healthrules", templateHrName + ".xml")
        if fn.endswith(".xml"):
            if os.path.exists( fn ):
                print( "Opening {0}".format(fn))
                r = xmlet.parse( fn )
                root = r.getroot()
                print( "HR NAME ", r.find('.//health-rule/name').text)
            else:
                print( "Healthrule file does not exist {0}".format(fn) )
        else:
            print( "Ignoring ", fn )

        rf = os.path.join(self.auth["APPD_CONFIG_DIR"], appName, "configuration", rulesFile + ".csv")
        with open( rf, newline='', encoding='utf-8-sig' ) as cf: # remove BOM (byte-order mark)
            ignoreHeaders = [ "OVERWRITE", "TIER" ]
            cr = csv.reader( cf )
            headers = [i for i in next(cr, None)]
            print( "Headers ", headers )
            for row in cr:
                overWrite = row[ 0 ] == "YES"
                hrName = row[ 1 ]
                for c in zip( headers, row ):
                    try:
                        header = c[0]
                        value = c[1]
                        if header not in ignoreHeaders and header.startswith("health-rule/"):
                            #print( "FIND [{0}] [{1}] [{2}]".format( hrName, header, ignoreHeaders) )
                            root.find(header).text = value
                    except Exception as e:
                        m = "Invalid header, Error updating {0} with {1} for {2}".format(header, value, hrName)
                        raise Exception( m )
                hrXML = xmlet.tostring(root, encoding='us-ascii', method='xml')
                d1 = os.path.join(self.auth["APPD_CONFIG_DIR"], appName, "healthrules", hrName + ".xml" )
                print( "Writing ", d1)
                with open(d1, 'w') as f1:
                    f1.write( hrXML.decode() )

    def readHealthRuleFile(self, appName, hrName):
        root = None
        fn = os.path.join(self.auth["APPD_CONFIG_DIR"], appName, "healthrules", hrName + ".xml")
        if fn.endswith(".xml"):
            if os.path.exists( fn ):
                print( "Opening {0}".format(fn))
                r = xmlet.parse( fn )
                root = r.getroot()
                print( "HR NAME ", r.find('.//health-rule/name').text)
            else:
                print( "Healthrule file does not exist {0}".format(fn) )
        else:
            print( "Ignoring ", fn )
        return root

    def writeHealthRuleFile(self, appName, hrName, root):
        hrXML = xmlet.tostring(root, encoding='us-ascii', method='xml')
        d1 = os.path.join(self.auth["APPD_CONFIG_DIR"], appName, "healthrules", hrName + ".xml" )
        print( "Writing ", d1)
        with open(d1, 'w') as f1:
            f1.write( hrXML.decode() )

    def rewriteHealthRules(self, rulesFile, appName):
        # Read health rules from file and reqrite based on rules file
        rf = os.path.join(self.auth["APPD_CONFIG_DIR"], appName, "configuration", rulesFile + ".csv")
        with open( rf, newline='', encoding='utf-8-sig' ) as cf: # remove BOM (byte-order mark)
            ignoreHeaders = [ "OVERWRITE", "TIER" ]
            cr = csv.reader( cf )
            headers = [i for i in next(cr, None)]
            print( "Headers ", headers )
            for row in cr:
                overWrite = row[ 0 ] == "YES"
                hrName = row[ 1 ]
                print( "Processing HR: {0}".format(hrName))
                root = self.readHealthRuleFile(appName, hrName)
                for c in zip( headers, row ):
                    try:
                        header = c[0]
                        value = c[1]
                        if header not in ignoreHeaders and header.startswith("health-rule/"):
                            print( "FIND [{0}] [{1}] [{2}] [{3}]".format( hrName, header, ignoreHeaders, value) )
                            root.find(header).text = value
                    except Exception as e:
                        m = "Invalid header, Error updating {0} with {1} for {2}".format(header, value, hrName)
                        raise Exception( m )
                self.writeHealthRuleFile(appName, hrName, root)


    def rewriteHealthRulesNew(self, rulesFile, appName):
        # Read health rules from file and reqrite based on rules file
        rf = os.path.join(self.auth["APPD_CONFIG_DIR"], appName, "configuration", rulesFile + ".csv")
        with open( rf, newline='', encoding='utf-8-sig' ) as cf: # remove BOM (byte-order mark)
            ignoreHeaders = [ "OVERWRITE", "TIER" ]
            cr = csv.reader( cf )
            headers = [i for i in next(cr, None)]   # Line 1
            variables = [i for i in next(cr, None)] # Line 2
            print( "Headers ", headers )
            for row in cr:
                overWrite = row[ headers.index('OVERWRITE') ] == "YES"
                hrName = row[ headers.index('HEALTH_RULE_NAME') ]
                s = [ { "var": i, "location": v.index(i), "value": "NONE" } for i in variables if i in [0,1,2,3,4,5,6,7,8]]
                print( "Processing HR: {0}".format(hrName))
                root = self.readHealthRuleFile(appName, hrName)
                for c in zip( headers, row ):
                    try:
                        header = c[0]
                        value = c[1]
                        if  not header.startswith("health-rule/"):
                            print( "FIND [{0}] [{1}] [{2}] [{3}]".format( hrName, header, ignoreHeaders, value) )
                            root.find(header).text = value
                    except Exception as e:
                        m = "Invalid header, Error updating {0} with {1} for {2}".format(header, value, hrName)
                        raise Exception( m )
                self.writeHealthRuleFile(appName, hrName, root)

    def loadHRFromRulesFile(self, rulesFile, appName):
        rf = os.path.join(self.auth["APPD_CONFIG_DIR"], appName, "configuration", rulesFile + ".csv")
        with open( rf, newline='', encoding='utf-8-sig' ) as cf: # remove BOM (byte-order mark)
            cr = csv.reader( cf )
            headers = [i for i in next(cr, None)]
            for row in cr:
                overWrite = row[ 0 ] == "YES"
                hrName = row[ 1 ]
                print( appName, hrName, overWrite )
                fn = os.path.join(self.auth["APPD_CONFIG_DIR"], appName, "healthrules", hrName + ".xml")
                self.loadHealthRuleFromFile(appName, fn, overWrite)

    def getAllBusinessTransactions(self, appName):
        # /controller/rest/applications/5/business-transactions
        appId = self.getAppId( appName )
        if appId > 0:
            r = self.auth['session'].get(self.httpURL("/controller/rest/applications/{0}/business-transactions?output=json".format(appId)), headers=self.httpHeaders())
            if r.status_code != 200:
                print("Authentication error ", r.status_code)
            else:
                j = json.loads( r.text )
                j = sorted(j, key=lambda k: k['name'], reverse=False)
                f1 = os.path.join(self.auth["APPD_CONFIG_DIR"], appName, "business-transactions", "bt.csv" )
                print( "Writing to {0}".format( f1 ))
                with open(f1, mode='w') as cf1:
                    headers = ['Name', 'Tier']
                    cw = csv.writer(cf1, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                    cw.writerow(headers)
                    for i in j:
                        cw.writerow( [ i['name'], i['tierName'] ] )

    def getTransactionSnapshots(self, appName):
        # /controller/rest/applications/5/business-transactions
        appId = self.getAppId( appName )
        if appId > 0:
            r = self.auth['session'].get(self.httpURL("/controller/rest/applications/{0}/request-snapshots?output=json".format(appId)), headers=self.httpHeaders())
            if r.status_code != 200:
                print("Authentication error ", r.status_code)
            else:
                j = json.loads( r.text )
                j = sorted(j, key=lambda k: k['name'], reverse=False)
                f1 = os.path.join(self.auth["APPD_CONFIG_DIR"], appName, "snapshots", "bt.csv" )
                print( "Writing to {0}".format( f1 ))
                with open(f1, mode='w') as cf1:
                    headers = ['Name', 'Tier']
                    cw = csv.writer(cf1, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                    cw.writerow(headers)
                    for i in j:
                        cw.writerow( [ i['name'], i['tierName'] ] )

    def analyticsMakeQuery(self, name, description, queryString):
        return {"name": str(uuid.uuid1()), # Time based UUUID
                "searchName": name, "adqlQueries":[queryString],"searchDescription": description,
                "searchType":"SINGLE", "searchMode":"ADVANCED", "viewMode":"DATA", "visualization":"TABLE",
                "selectedFields":["application","eventTimestamp","responseTime","transactionName","userExperience","segments.node","segments.tier"],
                "widgets":[]}

    def saveAnalyticsQuery(self, name, description, queryString):
        r = self.auth['session'].post(self.httpURL("/controller/restui/analyticsSavedSearches/createAnalyticsSavedSearch"),
                                 cookies=self.auth['session'].cookies,
                                 headers=self.auth['session'].headers,
                                 data=json.JSONEncoder().encode( self.analyticsMakeQuery(name, description, queryString ) ) )
        print( r.text )

    def analyticsMakeMetric(self, name, description, queryString):
        return {"queryName": name, "queryDescription": description,"adqlQueryString":queryString, "enabled": True,
                "eventType": "BIZ_TXN", "queryType": "ADQL_QUERY"}

    def createAnalyticsMetric(self, queryName, description, queryString):
        print( "Creating metric {0}".format(queryName))
        r = self.auth['session'].post(self.httpURL("/controller/restui/analyticsMetric/create"),
                                 cookies=self.auth['session'].cookies,
                                 headers=self.auth['session'].headers,
                                 data=json.JSONEncoder().encode( self.analyticsMakeMetric(queryName, description, queryString ) ) )
        print( r.text )

    def getAnalyticsMetrics(self):
        r = self.auth['session'].get(self.httpURL("/controller/restui/analyticsMetric/getAnalyticsScheduledQueryReports"),
                                 cookies=self.auth['session'].cookies,
                                 headers=self.auth['session'].headers)
        self.analyicsMetrics = json.loads(r.text)
        #print( self.analyicsMetrics )


    def deleteAnalyticsMetric(self, queryName):
        try:
            print( "Deleteing metric {0}".format(queryName))
            metric = [ i  for i in self.analyicsMetrics if i['queryName'] == queryName ][0]
            queryToDelete = {"adqlQueryString": metric['adqlQueryString'],"createdBy": metric['createdBy'],
                             "enabled":	metric['queryExecutionEnabled'],"eventType": metric['eventType'],
                             "queryDescription": metric['queryDescription'],"queryName": metric['queryName'], "queryType": 'ADQL_QUERY'}
            r = self.auth['session'].post(self.httpURL("/controller/restui/analyticsMetric/delete"),
                                     cookies=self.auth['session'].cookies,
                                     headers=self.auth['session'].headers,
                                     data=json.JSONEncoder().encode( queryToDelete ))
            print( r.text )
        except Exception as e:
            print( e )
            print( "Error: Metric not found {0}".format(queryName))

    def createAnalyticsMetricsFromFile(self, analyticsFile, appName):
        rf = os.path.join(self.auth["APPD_CONFIG_DIR"], appName, "configuration", analyticsFile + ".csv")
        with open( rf, newline='', encoding='utf-8-sig' ) as cf: # remove BOM (byte-order mark)
            cr = csv.reader( cf )
            headers = [i for i in next(cr, None)]
            for row in cr:
                overWrite = row[ 0 ] == "YES"
                queryName = row[ 1 ]
                queryDescription = row[ 2 ]
                queryString = row[ 3 ]
                if overWrite:
                    self.deleteAnalyticsMetric(queryName)
                    self.createAnalyticsMetric(queryName, queryDescription, queryString)
                else:
                    print( "Ignoring {0}".format(queryName))

    def getAccountInfo(self):
        r = self.auth['session'].get(self.httpURL("/controller/restui/user/account?output=json"),
                                 cookies=self.auth['session'].cookies,
                                 headers=self.auth['session'].headers)
        return json.loads(r.text)

    def getDatabaseCollectors(self):
        r = self.auth['session'].get(self.httpURL("/controller/rest/databases/collectors"),
                                 cookies=self.auth['session'].cookies,
                                 headers=self.auth['session'].headers)
        print( r.status_code )
        print( r.text )

    def createDatabaseCollector(self, collector):
        r = self.auth['session'].post(self.httpURL("/controller/rest/databases/create"),
                                 cookies=self.auth['session'].cookies,
                                 headers=self.auth['session'].headers,
                                 data=json.JSONEncoder().encode( collector ) )
        print( r.status_code )
        print( r.text )

    def getAllRoles(self):
        r = self.auth['session'].get(self.httpURL("/controller/api/rbac/v1/roles"),
            cookies=self.auth['session'].cookies, headers=self.auth['session'].headers)
        if r.status_code != 200:
            print("Authentication error ", r.status_code)
        else:
            print( r.status_code )
            print( r.text )

    def getRoleId(self, roleName):
        roleId = -1
        r = self.auth['session'].get(self.httpURL("/controller/api/rbac/v1/roles/name/{roleName}".format(roleName=roleName)),
            cookies=self.auth['session'].cookies, headers=self.auth['session'].headers)
        if r.status_code != 200:
            print("Authentication error ", r.status_code)
        else:
            print( r.status_code )
            print( r.text )
        j = json.loads( r.text )
        return j['id']

    def getRolePermissions(self, roleName):
        r = self.auth['session'].get(self.httpURL("/controller/api/rbac/v1/roles/name/{roleName}?include-permissions=true".format(roleName=roleName)),
            cookies=self.auth['session'].cookies, headers=self.auth['session'].headers)
        if r.status_code != 200:
            print("Authentication error ", r.status_code)
        else:
            print( r.status_code )
            j = json.loads( r.text )
            for i in j['permissions']:
                print( i )

    def createNewRole(self, roleName, newRoleName, applicationId=0):
        r = self.auth['session'].get(self.httpURL("/controller/api/rbac/v1/roles/name/{roleName}?include-permissions=true".format(roleName=roleName)),
            cookies=self.auth['session'].cookies, headers=self.auth['session'].headers)
        if r.status_code != 200:
            print("Authentication error ", r.status_code)
        else:
            j = json.loads( r.text )
            print( "Existing Role: {} New Role".format(j['name'],newRoleName ))

            # Remove id fields
            j.pop( 'id' ) # Remove id
            tmp1 = [ i.pop('id') for i in j['permissions'] ]

            # Update the Role Name
            j['name'] = newRoleName
            #for i in j['permissions']:
            #    print( i )
            # Update the Applicaiton id - using the 'entityId' field to reflect the application to apply this role to
            if applicationId > 0:
                # Update entityType = APPLICATION
                tmp1 = [ i.update( { 'entityId': applicationId } ) for i in j['permissions'] if i['entityType'] == "APPLICATION" ]

            print("Updated")
            #for i in j['permissions']:
            #    print( i )
            #print(self.auth['session'].headers )
            self.auth['session'].headers['Content-Type'] = "application/vnd.appd.cntrl+json;v=1"
            r = self.auth['session'].post(self.httpURL("/controller/api/rbac/v1/roles"),
                cookies=self.auth['session'].cookies, headers=self.auth['session'].headers,
                data=json.JSONEncoder().encode( j )  )
            print( r.status_code )
            print( r.text )

    def deleteRole(self, roleName):
        roleId = self.getRoleId( roleName )
        r = self.auth['session'].delete(self.httpURL("/controller/api/rbac/v1/roles/{roleId}".format(roleId=roleId)),
            cookies=self.auth['session'].cookies, headers=self.auth['session'].headers)
        if r.status_code != 200:
            print("Authentication error ", r.status_code)
        else:
            print( r.status_code )
            print( r.text )

cmd = sys.argv[1] if len(sys.argv) > 1 else "unknown command"


if cmd == "oauth":
    #self.auth'schemaName'] = sys.argv[2]
    a1 = APPD()
    a1.configure()
    a1.authenticateOauth()
    a1.print()
    a1.getAllAppIDs()
    a1.printAppIDs()

elif cmd == "bauth":
    #self.auth'schemaName'] = sys.argv[2]
    a1 = APPD()
    a1.configure()
    a1.authenticateBasic()
    a1.print()
    a1.getAllAppIDs()
    a1.printAppIDs()

elif cmd == "account":
     a1 = APPD()
     a1.configureBasic()
     a1.authenticateBasic()
     j = a1.getAccountInfo()
     print( j.keys() )
     print( "Access Key: ", j["account"]["accessKey"])
     print( "Account Name: ", j["account"]["name"])
     print( "Global Account Name: ", j["account"]["globalAccountName"])
     print( "Controller URL: ", j["account"]["controllerURL"])

elif cmd == "getAppId":
    applicationName = sys.argv[2]
    a1 = APPD()
    a1.configureBasic()
    a1.authenticateBasic()
    a1.getAllAppIDs()
    appId = a1.getAppId( applicationName )
    print( "Application {} ID {}".format(applicationName, appId ))

elif cmd == "getAllRoles":
    a1 = APPD()
    a1.configureBasic()
    a1.authenticateBasic()
    a1.getAllRoles()

elif cmd == "getRolePermissions":
    roleName = sys.argv[2]
    print( roleName )
    a1 = APPD()
    a1.configureBasic()
    a1.authenticateBasic()
    a1.getRolePermissions(roleName)

elif cmd == "createNewRole":
    roleName = sys.argv[2]
    newRoleName = sys.argv[3]
    print( roleName )
    a1 = APPD()
    a1.configureBasic()
    a1.authenticateBasic()
    a1.createNewRole(roleName, newRoleName)

elif cmd == "createNewRoleApply":
    roleName = sys.argv[2]
    newRoleName = sys.argv[3]
    applicationName = sys.argv[4]
    print( roleName )
    a1 = APPD()
    a1.configureBasic()
    a1.authenticateBasic()
    a1.getAllAppIDs()
    appId = a1.getAppId( applicationName )
    print( appId )
    a1.createNewRole(roleName, newRoleName, appId)

elif cmd == "deleteRole":
    roleName = sys.argv[2]
    a1 = APPD()
    a1.configureBasic()
    a1.authenticateBasic()
    a1.deleteRole(roleName)

elif cmd == "getDatabaseCollectors":
    # Save Analytics Search Query
    a1 = APPD()
    a1.configure()
    a1.authenticateBasic()
    a1.getDatabaseCollectors()

elif cmd == "createDatabaseCollectors":
    # Save Analytics Search Query
    c1 = '{"id":null,"version":0,"name":"DDR_TEST_100","nameUnique":true,"builtIn":false,"createdBy":null,"createdOn":1603551627000,"modifiedBy":null,"modifiedOn":1603551627000,"type":"MYSQL","hostname":"localhost","useWindowsAuth":false,"username":"root","password":"appdynamics_redacted_password","port":3306,"loggingEnabled":false,"enabled":true,"excludedSchemas":null,"jdbcConnectionProperties":[],"databaseName":"","failoverPartner":null,"connectAsSysdba":false,"useServiceName":false,"sid":"","customConnectionString":null,"enterpriseDB":false,"useSSL":false,"enableOSMonitor":false,"hostOS":null,"useLocalWMI":false,"hostDomain":null,"hostUsername":null,"hostPassword":null,"dbInstanceIdentifier":null,"region":null,"certificateAuth":false,"removeLiterals":false,"sshPort":0,"agentName":"JRS-Local-MySQL","dbCyberArkEnabled":false,"dbCyberArkApplication":null,"dbCyberArkSafe":null,"dbCyberArkFolder":null,"dbCyberArkObject":null,"hwCyberArkEnabled":false,"hwCyberArkApplication":null,"hwCyberArkSafe":null,"hwCyberArkFolder":null,"hwCyberArkObject":null,"orapkiSslEnabled":false,"orasslClientAuthEnabled":false,"orasslTruststoreLoc":null,"orasslTruststoreType":null,"orasslTruststorePassword":null,"orasslKeystoreLoc":null,"orasslKeystoreType":null,"orasslKeystorePassword":null,"ldapEnabled":false,"customMetrics":null,"subConfigs":[],"jmxPort":0,"backendIds":[],"extraProperties":[]},"licensesUsed":1}'

    c2 = '{ "type":"MYSQL","name":"localdocker_dbagent-MySQLCollector", "hostname":"mysql", "port":"3306", "username":"root", "password":"appdynamics_redacted_password", "enabled":true, "excludedSchemas":null, "databaseName":null, "failoverPartner":null, "connectAsSysdba":false, "useServiceName":false, "sid":null, "customConnectionString":null, "enterpriseDB":false, "useSSL":false, "enableOSMonitor":false, "hostOS":null, "useLocalWMI":false, "hostDomain":null, "hostUsername":null, "hostPassword":"", "dbInstanceIdentifier":null, "region":null, "certificateAuth":false, "removeLiterals":true, "sshPort":0, "agentName":"localdocker_dbagent", "dbCyberArkEnabled":false, "dbCyberArkApplication":null, "dbCyberArkSafe":null, "dbCyberArkFolder":null, "dbCyberArkObject":null, "hwCyberArkEnabled":false, "hwCyberArkApplication":null, "hwCyberArkSafe":null, "hwCyberArkFolder":null, "hwCyberArkObject":null, "orapkiSslEnabled":false, "orasslClientAuthEnabled":false, "orasslTruststoreLoc":null, "orasslTruststoreType":null, "orasslTruststorePassword":"", "orasslKeystoreLoc":null, "orasslKeystoreType":null, "orasslKeystorePassword":"", "ldapEnabled":false, "customMetrics":null, "subConfigs":[ { "type":"MYSQL", "name":"localdocker_dbagent-MySQLCollector sub-collector", "hostname":"mysql-remote", "port":"3388", "username":"root", "password":"different-password", "enabled":true, "excludedSchemas":null, "databaseName":null, "failoverPartner":null, "connectAsSysdba":false, "useServiceName":false, "sid":null, "customConnectionString":null, "enterpriseDB":false, "useSSL":false, "enableOSMonitor":false, "hostOS":null, "useLocalWMI":false, "hostDomain":null, "hostUsername":null, "hostPassword":"", "dbInstanceIdentifier":null, "region":null, "certificateAuth":false, "removeLiterals":true, "sshPort":0, "agentName":"localdocker_dbagent", "dbCyberArkEnabled":false, "dbCyberArkApplication":null, "dbCyberArkSafe":null, "dbCyberArkFolder":null, "dbCyberArkObject":null, "hwCyberArkEnabled":false, "hwCyberArkApplication":null, "hwCyberArkSafe":null, "hwCyberArkFolder":null, "hwCyberArkObject":null, "orapkiSslEnabled":false, "orasslClientAuthEnabled":false, "orasslTruststoreLoc":null, "orasslTruststoreType":null, "orasslTruststorePassword":"", "orasslKeystoreLoc":null, "orasslKeystoreType":null, "orasslKeystorePassword":"", "ldapEnabled":false, "customMetrics":null } ] }'
    print(c2)

    c3 = '{ "type":"MYSQL", "name":"DDR_TEST_MYSQL_100", "hostname":"achilles", "port":"3306", "username":"admin", "password":"foo", "agentName":"Default Database Agent" }'
    a1 = APPD()
    a1.configure()
    a1.authenticateBasic()
    a1.createDatabaseCollector( c3 )

elif cmd == "getAnalyticsMetrics":
    # Save Analytics Search Query
    a1 = APPD()
    a1.configure()
    a1.authenticateBasic()
    a1.getAnalyticsMetrics()

elif cmd == "deleteAnalyticsMetric":
    # Save Analytics Search Query
    name = sys.argv[2]
    a1 = APPD()
    a1.configure()
    a1.authenticateBasic()
    a1.getAnalyticsMetrics()
    a1.deleteAnalyticsMetric(name)

elif cmd == "createAnalyticsMetric":
    # Save Analytics Search Query
    name = sys.argv[2]
    description = sys.argv[3]
    query = sys.argv[4]
    a1 = APPD()
    a1.configure()
    a1.authenticateBasic()
    #a1.print()
    #a1.saveAnalyticsQuery(name, description, "SELECT count(*) FROM transactions" )
    a1.createAnalyticsMetric(name, description, query )

elif cmd == "createAnalyticsMetricsFromFile":
    # Save Analytics Search Query
    analyticsMetricConfigFile = sys.argv[2]
    appName = sys.argv[3]
    a1 = APPD()
    a1.configure()
    a1.authenticateBasic()
    #a1.print()
    a1.getAnalyticsMetrics()
    a1.createAnalyticsMetricsFromFile(analyticsMetricConfigFile, appName)

elif cmd == "getBTs":
    appName = sys.argv[2]
    a1 = APPD()
    a1.configure()
    a1.authenticateOauth()
    a1.getAllAppIDs()
    a1.printAppIDs()
    a1.createConfigDir()
    a1.getAllBusinessTransactions(appName)

elif cmd == "getHR-new":
    # Use the new Health Rule API
    # https://docs.appdynamics.com/display/PRO45/Health+Rule+API
    appName = sys.argv[2]
    hrName = sys.argv[3]
    a1 = APPD()
    a1.configure()
    a1.authenticateBasic()
    hr1 = a1.getHealthRulesNew(appId)
    print( hr )

elif cmd == "getHR":
    appName = sys.argv[2]
    hrName = sys.argv[3]
    a1 = APPD()
    a1.configure()
    a1.authenticateOauth()
    a1.getAllAppIDs()
    a1.printAppIDs()
    appId = a1.getAppId(appName)
    hr1 = a1.getHealthRule(appId, hrName)
    t = xmlet.fromstring( hr1 )
    print( "HR NAME ", t.find('.//health-rule/name').text)
    hrXML = xmlet.tostring(t, encoding='us-ascii', method='xml')
    print( "HR ID ", hrXML.decode() )

elif cmd == "testHR":
    appName = sys.argv[2]
    hrName = sys.argv[3]
    a1 = APPD()
    a1.configure()
    #a1.authenticateOauth()
    a1.authenticateBasic()
    a1.getAllAppIDs()
    a1.printAppIDs()
    appId = a1.getAppId(appName)
    hr1 = a1.testHealthRule(appId)


elif cmd == "hrStruct":
    appName = sys.argv[2]
    hrName = sys.argv[3]
    a1 = APPD()
    a1.configure()
    a1.healthruleStructure(appName, hrName)

elif cmd == "rewriteHr":
    # Rewrite the health rules listed in the rules files in the config dir
    # Use previously saved HR files
    rulesFile = sys.argv[2]
    appName = sys.argv[3]
    a1 = APPD()
    a1.configure()
    a1.rewriteHealthRules(rulesFile, appName)

elif cmd == "getAllHr":
    # Get all health rules for this app
    appName = sys.argv[2]
    a1 = APPD()
    a1.configure()
    a1.authenticateOauth()
    a1.getAllAppIDs()
    a1.printAppIDs()
    a1.createConfigDir()
    a1.getAllHealhRules( appName )

elif cmd == "loadAllHrFromDir":
    # Load all health rules from the app config dir
    appName = sys.argv[2]
    a1 = APPD()
    a1.configure()
    a1.authenticateOauth()
    a1.getAllAppIDs()
    a1.loadFromRulesDir( appName, overWrite=True )

elif cmd == "createHealthRules":
    rulesFile = sys.argv[2]
    appName = sys.argv[3]
    templateHrName = sys.argv[4]
    a1 = APPD()
    a1.configure()
    a1.authenticateOauth()
    a1.getAllAppIDs()
    a1.createHealthRules(rulesFile, appName, templateHrName)

elif cmd == "loadHrFromRulesFile":
    # Only load  health rules from the rules file
    rulesFile = sys.argv[2]
    appName = sys.argv[3]
    a1 = APPD()
    a1.configure()
    a1.authenticateOauth()
    a1.getAllAppIDs()
    a1.loadHRFromRulesFile(rulesFile, appName)

elif cmd == "loadHr":
    appName = sys.argv[2]
    hrName = sys.argv[3]
    a1 = APPD()
    a1.configure()
    a1.authenticateOauth()
    a1.getAllAppIDs()
    a1.printAppIDs()
    a1.createConfigDir()
    a1.loadHealthRuleFromFile( appName, hrName + ".xml", overWrite=True )

else:
    print( "Commands: getAllHr,rewriteHr, rewriteHr")
    print( "python3 healthrules.py rewriteHr <rules.csv> <App Name> <base-hr-template>")
    print( "python3 healthrules.py <rules.csv> <App Name>")
    print( "python3 healthrules.py getAllHr <App Name>" )
    print( "python3 healthrules.py createAnalyticsMetricsFromFile <analytics metrics file> analyticsApplication")
    print( "python3 healthrules.py loadHrFromRulesFile <analytis-hr-file> analyticsApplication")
