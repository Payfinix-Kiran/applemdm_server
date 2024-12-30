# main/routes.py

import json
import requests
import httpx
import time
import jwt
from flask import request, Blueprint, jsonify, make_response, send_file, Response
from plistlib import loads
import plistlib
from scep import Client
import os
from base64 import b64encode
import base64
from enum import Enum
import OpenSSL
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_der_x509_csr,load_pem_x509_csr
from cryptography.x509.oid import NameOID
import datetime
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.hashes import SHA256
# from asn1crypto import x509, pem

class PKIStatus(Enum):
    """The SCEP PKI Status

    Decimal value as printableString

    See Also:
        - SCEP RFC Section 3.2.1.3.
    """
    SUCCESS = '0'
    FAILURE = '2'
    PENDING = '3'

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
        mobileconfig_path = "scep-sig.mobileconfig"

        return send_file(mobileconfig_path, as_attachment=True, mimetype="application/x-apple-aspen-config")

    except Exception as e:
        print(f"Error serving mobileconfig: {e}")
        return {"error": str(e)}, 500
    
CA_CERT_FILE = 'cacert.der'
CA_KEY_FILE = 'ca_key.pem'

# Load the certificate in DER format
with open(CA_CERT_FILE, 'rb') as cert_file:
    ca_cert_data = cert_file.read()

# ca_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, ca_cert_data)

# Load the private key (assuming it's in PEM format)
ca_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, open(CA_KEY_FILE).read())


@main.route('/scep', methods=['GET', 'POST'])
def scep():
    operation = request.args.get('operation')

    if operation == 'GetCACert':
        with open(CA_CERT_FILE, 'rb') as cert_file:
            ca_cert_data = cert_file.read()
            print(type(ca_cert_data)) 

        try:
            
            # try:
            #     cert = x509.load_pem_x509_certificate(ca_cert_data, backend=default_backend())
            #     print("Loaded PEM certificate.")

            #     cert_data = cert.public_bytes(
            #     encoding=serialization.Encoding.PEM
            # )
            # except ValueError:
            #     # If PEM fails, try loading as DER
            #     # cert_data = x509.load_der_x509_certificate(ca_cert_data, backend=default_backend())
            #     print("Loaded DER certificate.")
            

            # Return the certificate as a Response in PEM format
            return Response(ca_cert_data, content_type='application/x-x509-ca-cert')

        except Exception as e:
            print(f"Error loading certificate: {e}")
            return 'Error processing certificate', 500
    
    elif operation == 'GetCACaps':
        return provide_ca_caps()

    elif operation == 'PKIOperation':
        csr_data = request.data
        print("CSR Data:", csr_data.hex()[:100])
        with open('csr.der', 'wb') as f:
            f.write(csr_data)
        try:
            return Response(csr_data, content_type='application/pkcs7-mime', status=200)
        except Exception as e:
            print(f"Error loading certificate: {e}")
            return 'Error processing certificate', 500

    elif operation == 'GetCRL':
        serial_number = request.args.get('serial_number')
        return Response(serial_number, content_type='text/plain')

    else:
        return jsonify({'error': 'Invalid operation'}), 400

@main.route('/mdm/scep', methods=['GET', 'POST'])
def scep_mdm():
    operation = request.args.get('operation')
    
    if operation == 'GetCACert':
        try:
            client = Client.Client(
            'https://cf49-49-207-210-161.ngrok-free.app/scep'
        )
            ca_certificate = client.rollover_certificate()
            print(ca_certificate)
            return Response(ca_certificate, content_type='application/x-x509-ca-cert')
        except Exception as e:
            return jsonify({'error': str(e)}), 500
        
    elif operation == 'GetCACaps':
        return provide_ca_caps()
    
    elif operation == 'PKIOperation':
        # Handle PKIOperation (e.g., Enrollment)
        try:
            csr = request.data  # CSR data sent by the client
            identity, identity_private_key = Client.SigningRequest.generate_self_signed(
                cn='MDM-SCEP',
                key_usage={'digital_signature', 'key_encipherment'}
            )
            response = client.enrol(
                csr=csr,
                identity=identity,
                identity_private_key=identity_private_key,
                identifier=None
            )
            if response.status == Client.PKIStatus.FAILURE:
                return jsonify({'error': response.fail_info}), 400
            elif response.status == Client.PKIStatus.PENDING:
                return jsonify({'transaction_id': response.transaction_id}), 202
            else:
                return Response(response.certificate, content_type='application/x-x509-user-cert')
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    elif operation == 'GetCRL':
        # Handle GetCRL operation
        try:
            serial_number = request.args.get('serial_number')
            identity, identity_private_key = Client.SigningRequest.generate_self_signed(
                cn='MDM-SCEP',
                key_usage={'digital_signature', 'key_encipherment'}
            )
            response = client.get_crl(
                identity=identity,
                identity_private_key=identity_private_key,
                serial_number=int(serial_number)
            )
            if response.status == Client.PKIStatus.FAILURE:
                return jsonify({'error': response.fail_info}), 400
            else:
                return Response(response.crl, content_type='application/pkix-crl')
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    else:
        return jsonify({'error': 'Invalid operation'}), 400

def provide_ca_caps():
    capabilities = "POSTPKIOperation\nSHA-256\nAES\nDES3\n"
    response = make_response(capabilities)
    response.headers['Content-Type'] = 'text/plain'
    return response

# @main.route('/mdm/getjwt', methods=['GET'])
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

    jwt_token = getjwt()

    payload = {
        "aps": {
            "alert": "Hello from CruxAppleMDM!",
            "sound": "default",
            "badge": 1
        }
    }

    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Content-Type": "application/json",
        "apns-topic": "com.sujanix.cruxapplemdm"
    }
    with httpx.Client(http2=True) as client:
        response = client.post(url, data=json.dumps(payload), headers=headers)
        print(response.content)

        if response.status_code == 200:
            print("Notification sent successfully!")
            return jsonify({"message": "Notification sent successfully!"}), 200
        else:
            print(f"Failed to send notification: {response.status_code} - {response.text}")
            return jsonify({"error": f"Failed to send notification: {response.status_code} - {response.text}"}), 400

@main.route('/generate_cer', methods=['GET'])
def generate_cer():
    identity, identity_private_key = Client.SigningRequest.generate_self_signed(
        cn='PyScep-test',
        key_usage={'digital_signature', 'key_encipherment'}
    )

    cert_pem = identity.to_pem()
    private_key_pem = identity_private_key.to_pem()

    cert_file_path = 'scep_cer.pem'
    private_key_file_path = 'scep_private_key.pem'


    with open(cert_file_path, 'wb') as cert_file:
        cert_file.write(cert_pem)

    with open(private_key_file_path, 'wb') as private_key_file:
        private_key_file.write(private_key_pem)

    return f"Certificate and Private Key saved to {cert_file_path} and {private_key_file_path}"

@main.route('/generate_csr', methods=['GET'])
def generate_csr():
    csr, private_key = Client.SigningRequest.generate_csr(
    cn='PyScep-test', 
    key_usage={'digital_signature', 'key_encipherment'}, 
    password='Sujanix#123'
)

    csr_pem = csr.to_pem()
    private_key_pem = private_key.to_pem()

    csr_file_path = 'scep_csr.pem'
    private_key_file_path = 'scep_key.pem'

    with open(csr_file_path, 'wb') as csr_file:
        csr_file.write(csr_pem)

    with open(private_key_file_path, 'wb') as private_key_file:
        private_key_file.write(private_key_pem)

    return f"CSR and Private Key saved to {csr_file_path} and {private_key_file_path}"

@main.route('/enroll_server', methods=['GET'])
def enroll_server():
    try:
        # Create the client for the SCEP server
        client = Client.Client(
            'https://cf49-49-207-210-161.ngrok-free.app/scep'
        )

        # Generate CSR and private key
        csr, private_key = Client.SigningRequest.generate_csr(
            cn='*.ngrok-free.app', 
            key_usage={'digital_signature', 'key_encipherment'}, 
            password='Sujanix#123'
        )

        # Generate identity
        identity, identity_private_key = Client.SigningRequest.generate_self_signed(
            cn='*.ngrok-free.app',
            key_usage={'digital_signature', 'key_encipherment'}
        )

        identifier = 'ngrokSCEP'

        # Perform enrollment
        res = client.enrol(
            csr=csr,
            identity=identity,
            identity_private_key=identity_private_key,
            identifier=identifier
        )

        print(res)

        # Handle response
        if res.status == PKIStatus.FAILURE:
            return f"Enrollment failed: {res.fail_info}", 400
        elif res.status == PKIStatus.PENDING:
            return f"Enrollment pending. Transaction ID: {res.transaction_id}", 202
        else:
            return f"Enrollment successful! Certificate: {res.certificate}", 200

    except requests.exceptions.SSLError as ssl_error:
        return f"SSL Error: {ssl_error}", 500
    except Exception as e:
        return f"Error: {e}", 500
