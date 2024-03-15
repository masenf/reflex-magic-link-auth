import datetime

AUTH_ROUTE = "/magic-link-auth"
DEFAULT_OTP_EXPIRATION_DELTA = datetime.timedelta(minutes=30)
DEFAULT_AUTH_SESSION_EXPIRATION_DELTA = datetime.timedelta(days=7)
DEFAULT_OTP_RATE_LIMIT = 5
