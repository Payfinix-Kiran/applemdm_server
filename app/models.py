# app/models.py

class Device:
    def __init__(self, device_id, device_token, status="pending"):
        self.device_id = device_id
        self.device_token = device_token
        self.status = status
        self.profiles = []

class Profile:
    def __init__(self, profile_id, profile_data):
        self.profile_id = profile_id
        self.profile_data = profile_data
