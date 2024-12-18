from apns2.client import APNsClient
from apns2.payload import Payload

def send_apns_notification(device_token, push_magic, bundle_id):
    """
    Sends an MDM push notification via APNs.

    Args:
        device_token (str): The device token for the MDM device.
        push_magic (str): The PushMagic token from MDM enrollment.
        bundle_id (str): The bundle ID of your MDM app.
    """
    # MDM notifications require an empty payload with the PushMagic
    payload = Payload(custom={"mdm": push_magic})

    # APNs client setup with the combined.pem file
    client = APNsClient('combined.pem', use_sandbox=True)

    # Sending the notification
    try:
        response = client.send_notification(device_token, payload, topic=bundle_id)
        print("Notification sent successfully:", response)
    except Exception as e:
        print("Error sending notification:", e)
