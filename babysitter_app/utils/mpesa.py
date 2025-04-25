# import base64
# import requests
# from datetime import datetime
# from django.conf import settings

# def get_mpesa_access_token():
#     credentials = f"{settings.MPESA_CONSUMER_KEY}:{settings.MPESA_CONSUMER_SECRET}"
#     encoded = base64.b64encode(credentials.encode()).decode()

#     headers = {
#         "Authorization": f"Basic {encoded}"
#     }

#     response = requests.get(settings.MPESA_TOKEN_URL, headers=headers)
#     if response.status_code == 200:
#         return response.json().get("access_token")
#     print("Failed to fetch access token:", response.text)
#     return None

# def generate_mpesa_password():
#     timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
#     raw_password = f"{settings.MPESA_SHORTCODE}{settings.MPESA_PASSKEY}{timestamp}"
#     encoded_password = base64.b64encode(raw_password.encode()).decode()
#     return encoded_password, timestamp
