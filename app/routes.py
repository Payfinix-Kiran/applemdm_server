# main/routes.py

import json
import requests
import httpx
import time
import jwt
from flask import request, Blueprint, jsonify, send_from_directory, send_file
from plistlib import loads
import plistlib
import uuid
import os
from base64 import b64encode
import base64

main = Blueprint('main', __name__)


@main.route('/mdm/command', methods=['PUT'])
def mdm_command_ack():
    try:
        # Parse the incoming JSON payload
        command_data = request.get_json()

        # Extract key details
        status = command_data.get("Status")
        command_uuid = command_data.get("CommandUUID")
        response = command_data.get("Response")

        print(f"Command Acknowledged: Status={status}, CommandUUID={command_uuid}, Response={response}")

        # Process the response (e.g., update database, trigger next command)

        return {"status": "success"}, 200

    except Exception as e:
        print(f"Error processing command acknowledgment: {e}")
        return {"error": str(e)}, 400


mdm_commands = dict()


@main.route("/mdm/commands", methods=["GET"])
# def get_commands():
#     # Example endpoint to return all MDM commands
#     global mdm_commands
#     return jsonify(mdm_commands)
def setup_commands():
    """
    Generates a dictionary of valid MDM commands.
    Handles configuration profiles, provisioning profiles,
    and dynamically builds a list of supported commands.
    """
    ret_list = {}

    # Static commands
    for cmd in ['DeviceLock', 'ProfileList', 'Restrictions',
                'CertificateList', 'InstalledApplicationList',
                'ProvisioningProfileList',
                'ManagedApplicationList']:  # iOS 5+ support
        ret_list[cmd] = {"Command": {"RequestType": cmd}}

    # Security Info Command
    ret_list['SecurityInfo'] = {
        "Command": {
            "RequestType": "SecurityInfo",
            "Queries": [
                "HardwareEncryptionCaps", "PasscodePresent",
                "PasscodeCompliant", "PasscodeCompliantWithProfiles"
            ]
        }
    }

    # Device Information Command
    ret_list['DeviceInformation'] = {
        "Command": {
            "RequestType": "DeviceInformation",
            "Queries": [
                "AvailableDeviceCapacity", "BluetoothMAC", "BuildVersion",
                "CarrierSettingsVersion", "CurrentCarrierNetwork",
                "CurrentMCC", "CurrentMNC", "DataRoamingEnabled",
                "DeviceCapacity", "DeviceName", "ICCID", "IMEI", "IsRoaming",
                "Model", "ModelName", "ModemFirmwareVersion", "OSVersion",
                "PhoneNumber", "Product", "ProductName", "SIMCarrierNetwork",
                "SIMMCC", "SIMMNC", "SerialNumber", "UDID", "WiFiMAC", "UnlockToken",
                "MEID", "CellularTechnology", "BatteryLevel",
                "SubscriberCarrierNetwork", "VoiceRoamingEnabled",
                "SubscriberMCC", "SubscriberMNC", "DataRoaming", "VoiceRoaming",
                "JailbreakDetected"
            ]
        }
    }

    # Clear Passcode Command
    ret_list['ClearPasscode'] = {
        "Command": {
            "RequestType": "ClearPasscode",
            # Add UnlockToken dynamically as needed
        }
    }

    # Install/Remove Configuration Profiles
    if os.path.exists('Example.mobileconfig'):
        with open('Example.mobileconfig', 'rb') as f:
            profile_data = f.read()
        plist = plistlib.loads(profile_data)

        ret_list['InstallProfile'] = {
            "Command": {
                "RequestType": "InstallProfile",
                "Payload": b64encode(profile_data).decode('utf-8')
            }
        }

        ret_list['RemoveProfile'] = {
            "Command": {
                "RequestType": "RemoveProfile",
                "Identifier": plist.get('PayloadIdentifier', 'Unknown')
            }
        }
    else:
        print("Warning: Example.mobileconfig not found.")

    # Install/Remove Provisioning Profiles
    if os.path.exists('MyApp.mobileprovision'):
        with open('MyApp.mobileprovision', 'rb') as f:
            provisioning_profile = f.read()

        ret_list['InstallProvisioningProfile'] = {
            "Command": {
                "RequestType": "InstallProvisioningProfile",
                "ProvisioningProfile": b64encode(provisioning_profile).decode('utf-8')
            }
        }

        # UUID placeholder for RemoveProvisioningProfile
        ret_list['RemoveProvisioningProfile'] = {
            "Command": {
                "RequestType": "RemoveProvisioningProfile",
                "UUID": "YOUR_PROVISIONING_PROFILE_UUID"  # Replace dynamically
            }
        }
    else:
        print("Warning: MyApp.mobileprovision not found.")

    # Install/Remove Applications
    ret_list['InstallApplication'] = {
        "Command": {
            "RequestType": "InstallApplication",
            "ManagementFlags": 4,  # Do not delete app when unenrolling
            "iTunesStoreID": 471966214  # Example: iTunes Movie Trailers
        }
    }

    ret_list['RemoveApplication'] = {
        "Command": {
            "RequestType": "RemoveApplication",
            "Identifier": "com.apple.movietrailers"
        }
    }

    # Custom Application Installation (if manifest and IPA exist)
    if os.path.exists('MyApp.ipa') and os.path.exists('Manifest.plist'):
        ret_list['InstallCustomApp'] = {
            "Command": {
                "RequestType": "InstallApplication",
                "ManifestURL": "https://YOUR_SERVER/manifest",
                "ManagementFlags": 1  # Delete app when unenrolling
            }
        }
    else:
        print("Warning: MyApp.ipa or Manifest.plist not found.")

    # Settings Command
    ret_list['Settings'] = {
        "Command": {
            "RequestType": "Settings",
            "Settings": [
                {"Item": "DataRoaming", "Enabled": False},
                {"Item": "VoiceRoaming", "Enabled": True}
            ]
        }
    }

    return ret_list


@main.route('/mdm/checkin', methods=['PUT'])
def mdm_checkin():
    try:
        # Read and parse the incoming plist data
        plist_data = request.data  # Raw data from the device
        # Parse plist into a Python dictionary
        checkin_data = loads(plist_data)

        # Extract important fields
        message_type = checkin_data.get('MessageType')
        push_magic = checkin_data.get('PushMagic')
        device_token = checkin_data.get('Token')
        topic = checkin_data.get('Topic')
        udid = checkin_data.get('UDID')

        # Decode the Base64 device token
        if device_token:
            device_token = base64.b64decode(device_token).hex()

        # Log or save the details
        print(f"Received Check-In: MessageType={message_type}, UDID={udid}, "
              f"PushMagic={push_magic}, Token={device_token}, Topic={topic}")

        # Respond with success (empty plist response as per MDM protocol)
        response_data = {}  # Apple expects an empty response for check-ins
        return response_data, 200, {'Content-Type': 'application/xml'}

    except Exception as e:
        print(f"Error processing Check-In: {e}")
        return jsonify({"status": "error", "message": str(e)}), 400


# def create_enrollment_profile():
#     profile = {
#         'PayloadContent': [
#             {
#                 'AutoJoin': True,
#                 'CaptiveBypass': False,
#                 'DisableAssociationMACRandomization': False,
#                 'EncryptionType': 'WPA',
#                 'HIDDEN_NETWORK': False,
#                 'IsHotspot': False,
#                 'Password': 'sujanix#123',
#                 'PayloadDescription': 'Configures Wi-Fi settings',
#                 'PayloadDisplayName': 'Wi-Fi',
#                 'PayloadIdentifier': f"com.apple.wifi.managed.{str(uuid.uuid4())}",
#                 'PayloadType': 'com.apple.wifi.managed',
#                 'PayloadUUID': str(uuid.uuid4()),
#                 'PayloadVersion': 1,
#                 'ProxyType': 'None',
#                 'SSID_STR': 'SUJANIX_5G'
#             }
#         ],
#         'PayloadDisplayName': 'wifi-config',
#         'PayloadIdentifier': f"Sujanixs-Laptop.{str(uuid.uuid4())}",
#         'PayloadRemovalDisallowed': False,
#         'PayloadType': 'Configuration',
#         'PayloadUUID': str(uuid.uuid4()),
#         'PayloadVersion': 1
#     }
#     return plistlib.dumps(profile)


# @main.route('/mdm/enroll', methods=['GET'])
# def enroll_device():
#     profile = create_enrollment_profile()
#     response = jsonify({"status": "Enrollment initiated"})
#     response.headers['Content-Type'] = 'application/x-apple-aspen-config'
#     response.data = profile
#     return response

@main.route('/mdm/enroll', methods=['GET'])
def enroll():
    try:
        mobileconfig_path = "profile-sig.mobileconfig"

        return send_file(mobileconfig_path, as_attachment=True, mimetype="application/x-apple-aspen-config")

    except Exception as e:
        print(f"Error serving mobileconfig: {e}")
        return {"error": str(e)}, 500


@main.route('/mdm/getjwt', methods=['GET'])
def getjwt():

    team_id = 'H5GZ7YMP42'
    key_id = 'QM368JN9D6'
    private_key_path = 'AuthKey_QM368JN9D6.p8'

    with open(private_key_path, 'r') as f:
        private_key = f.read()

    iat = int(time.time())
    payload = {
        'iss': team_id,
        'iat': iat,
    }

    headers = {
        'alg': 'ES256',
        'kid': key_id,
    }

    encoded_jwt = jwt.encode(payload, private_key,
                             algorithm='ES256', headers=headers)

    print(encoded_jwt)
    return encoded_jwt


@main.route('/mdm/sendnotification', methods=['GET'])
def send_notification():

    url = "https://api.sandbox.push.apple.com/3/device/89782f6151b882f680df1de9b9a3d259f6a895820d586abf26b8312f8f2adf53"

    # Your JWT token that you generated
    jwt_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IlFNMzY4Sk45RDYifQ.eyJpc3MiOiJINUdaN1lNUDQyIiwiaWF0IjoxNzMyNjk5OTQ1fQ.v-rXQL2JeB9BWUtUd6LnU57nlM7q-3DDOVm0HyhD0IX1ARTj4ucxtZ65AaVC5Ax6SQ_wESnc05E4rhJP7kYNJA"

    # The push notification payload
    payload = {
        "aps": {
            "alert": "Hello from CruxAppleMDM!",
            "sound": "default",
            "badge": 1
        }
    }

    # Set up the headers for the request
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Content-Type": "application/json",
        "apns-topic": "com.sujanix.cruxapplemdm"  # Your app's bundle identifier
    }
    # Use httpx to make the request with HTTP/2 support
    with httpx.Client(http2=True) as client:
        response = client.post(url, data=json.dumps(payload), headers=headers)
        print(response.content)
        # Check the response from APNs
        if response.status_code == 200:
            print("Notification sent successfully!")
            return jsonify({"message": "Notification sent successfully!"}), 200
        else:
            print(f"Failed to send notification: {
                  response.status_code} - {response.text}")
            return jsonify({"error": f"Failed to send notification: {response.status_code} - {response.text}"}), 400
