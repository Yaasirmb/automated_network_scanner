import requests
import json
from config import tenable_access_key, tenable_secret_key


def id_search(all_assets,search_name):
    """ Searches for matching asset names in Tenable, and if there's a match it returns the ID of the asset."""
    try:
        match = next(asset for asset in all_assets if asset['name'] == search_name)
        asset_id = match['id']
    except:
        asset_id = None
    return asset_id


def tenable_asset_maker(asset_name,ip_address):

    """
    Function that takes in IP addresses and pushes them up to Tenable.sc as a static asset using their API. 
    Returns the status code of the API call, if the status code is 200, it was a success. 
    """
    # For more info on the Tenable.sc API, check out their documentation:
    # https://docs.tenable.com/tenablesc/api_best_practices/Content/ScApiBestPractices/AddAssetDataToSC.htm
    # https://docs.tenable.com/tenablesc/api/Asset.htm#AssetRESTReference-/asset/import

    payload ={
    "name": "%s"%asset_name,
    "description": "%s ips from the Python script."%asset_name,
    "type": "static",
    "definedIPs": ""

    }

    headers = {

    "x-apikey": "accesskey=%s; secretkey=%s;"%(tenable_access_key,tenable_secret_key),
    "Accept": "application/json",
    "Content-Type": "application/json"

    }
  
    payload['definedIPs'] = ip_address

    url = "https://your-tenable-instance/rest/asset"
    asset_filter = "?filter=manageable"

    response = requests.request("GET",url+asset_filter,verify ='./your_cert.cer',headers=headers)
    raw_response = response.text
    dict_response = json.loads(raw_response)
    manageable_assets = dict_response['response']['manageable']

    asset_id = id_search(manageable_assets,asset_name)

    if asset_id == None:
        response = requests.request("POST", url, verify ='./your_cert.cer', json=payload, headers=headers)
        print("Created a new asset in Tenable.")
    else:

        patch_payload = {"definedIPs": ""}
        # Gets all information about the asset associated with a specific id. 
        asset_info = requests.get(url+'/%i'%int(asset_id),verify ='./your_cert.cer',headers=headers)
        raw_asset_info = asset_info.text
        dict_asset_info = json.loads(raw_asset_info)
        # All the ips in the asset currently.
        defined_ips = dict_asset_info['response']['typeFields']['definedIPs']
        # Readding IPs in the asset and then adding the ones I want to send.
        patch_payload['definedIPs'] = defined_ips + ',' + ip_address
        # Note that while the PATCH method works, it REPLACES the old assets with the new ones.
        update_asset = requests.patch(url+'/%i'%int(asset_id),json=patch_payload,verify ='./your_cert.cer',headers=headers)
        api_status_code = update_asset.status_code
        print("This asset is already in Tenable. If new assets were found using masscan the asset was updated.")

        return api_status_code
