# main/routes.py

import json
import requests
import httpx
import time
import jwt
from flask import request, Blueprint, jsonify, send_from_directory
import plistlib
import uuid
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


@main.route('/mdm/checkin', methods=['PUT'])
def mdm_checkin():
    try:
        # Parse the JSON payload
        checkin_data = request.get_json()

        # Extract the important fields
        push_magic = checkin_data.get('PushMagic')
        device_token = checkin_data.get('Token')
        topic = checkin_data.get('Topic')

        # Decode the device token (it is Base64 encoded)
        device_token = base64.b64decode(device_token).hex()

        # Log or save the details
        print(f"Received Check-In: PushMagic={push_magic}, Token={device_token}, Topic={topic}")

        # Respond with a success message
        return jsonify({"status": "success"}), 200

    except Exception as e:
        print(f"Error processing Check-In: {e}")
        return jsonify({"status": "error", "message": str(e)}), 400


def create_enrollment_profile():
    profile = {
        'PayloadContent': [
            {
                'PayloadType': 'com.apple.mdm',
                'PayloadVersion': 1,
                'PayloadIdentifier': 'com.sujanix.cruxapplemdm.mdm',
                'PayloadUUID': str(uuid.uuid4()),
                'PayloadDisplayName': 'MDM Profile',
                'PayloadDescription': 'Device management settings for your organization',
                'ServerURL': 'https://192.168.0.188:5000/mdm/checkin',
                'Topic': 'com.sujanix.cruxapplemdm',
                'CheckInURL': 'https://192.168.0.188:5000/mdm/checkin',
                'AccessRights': 8191,
                'SignMessage': True,
                'CheckOutWhenRemoved': True,
                'IdentityCertificateUUID': str(uuid.uuid4())
            },
            {
                'PayloadType': 'com.apple.wifi.managed',
                'PayloadVersion': 1,
                'PayloadIdentifier': 'com.sujanix.cruxapplemdm.wifi',
                'PayloadUUID': str(uuid.uuid4()),
                'SSID_STR': 'SUJANIX_5G',
                'HIDDEN_NETWORK': False,
                'AUTO_JOIN': True,
                'EncryptionType': 'WPA',
                'Password': 'sujanix#123'
            }
        ],
        'PayloadIdentifier': 'com.sujanix.cruxapplemdm.mdm',
        'PayloadUUID': str(uuid.uuid4()),
        'PayloadVersion': 1,
        'PayloadType': 'Configuration',
        'PayloadDisplayName': 'MDM Enrollment Profile',
        'PayloadDescription': 'Profile to enroll device in MDM'
    }
    return plistlib.dumps(profile)


@main.route('/mdm/enroll', methods=['GET'])
def enroll_device():
    profile = create_enrollment_profile()
    response = jsonify({"status": "Enrollment initiated"})
    response.headers['Content-Type'] = 'application/x-apple-aspen-config'
    response.data = profile
    return response


@main.route('/mdm/getjwt', methods=['GET'])
def getjwt():

    team_id = 'H5GZ7YMP42'  # Your 10-character Team ID
    key_id = 'QM368JN9D6'  # Your 10-character Key ID from Apple
    private_key_path = 'AuthKey_QM368JN9D6.p8'  # Path to your .p8 private key file

    # Load the private key from the .p8 file
    with open(private_key_path, 'r') as f:
        private_key = f.read()

    # Prepare the JWT claims
    iat = int(time.time())  # "Issued at" time (current time)
    payload = {
        'iss': team_id,  # Your Apple Developer Team ID
        'iat': iat,      # Issue time
    }

    # Define the JWT header
    headers = {
        'alg': 'ES256',  # Encryption algorithm (required for APNs)
        'kid': key_id,   # Your Key ID from Apple
    }

    # Generate the JWT
    encoded_jwt = jwt.encode(payload, private_key,
                             algorithm='ES256', headers=headers)

    # Output the JWT token
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
            print(f"Failed to send notification: {response.status_code} - {response.text}")
            return jsonify({"error": f"Failed to send notification: {response.status_code} - {response.text}"}), 400

