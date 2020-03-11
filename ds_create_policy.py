from __future__ import print_function
import sys, warnings
import deepsecurity
import json
from deepsecurity.rest import ApiException
from pprint import pprint

def createpolicy(fileScript):
    # Setup
    if not sys.warnoptions:
            warnings.simplefilter("ignore")
    configuration = deepsecurity.Configuration()
    configuration.host = 'https://app.deepsecurity.trendmicro.com/api'

    # Authentication
    configuration.api_key['api-secret-key'] = 'apisecret'

    # Initialization
    # Set Any Required Values
    api_instance = deepsecurity.PoliciesApi(deepsecurity.ApiClient(configuration))
    """policy = deepsecurity.Policy()"""
    api_version = 'v1'
    overrides = False

    with open(sys.argv[1]) as json_file:
        data = json.load(json_file)

    policy = data

    print("\n"+data["name"])
    print("Antimalware: "+data["antiMalware"]["state"])
    print("WebReputation: "+data["webReputation"]["state"])
    print("Firewall: "+data["firewall"]["state"])
    print("Intrusion Prevention: "+data["intrusionPrevention"]["moduleStatus"]["status"]+":"+data["intrusionPrevention"]["state"])
    print("Integrity Monitoring: "+data["integrityMonitoring"]["state"])
    print("Log Inspection: "+data["logInspection"]["state"])
    print("Application Control: "+data["applicationControl"]["state"]+"\n")
    try:
        api_response = api_instance.create_policy(policy, api_version, overrides=overrides)
        pprint("Policy ID: "+api_response.id)
        pprint("Policy Created")
    except ApiException as e:
        print("The requested Policy name already exists")

createpolicy(sys.argv[0])
