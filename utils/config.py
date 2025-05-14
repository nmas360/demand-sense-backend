from utils.imports import *

# Load environment variables
load_dotenv()

# Set environment variable to allow OAuth to work over HTTP (only for development)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = os.environ.get("OAUTHLIB_INSECURE_TRANSPORT")

# Secret key for JWT and session
SECRET_KEY = os.environ.get("JWT_KEY")

# Google OAuth configuration
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
GOOGLE_AUTH_BASE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"

# OAuth scopes
SCOPE = [
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/drive.file",
]

REDIRECT_URI = os.environ.get("GOOGLE_REDIRECT_URI")
FRONTEND_BASE_URL = os.environ.get("FRONTEND_BASE_URL")

# BigQuery config
BIGQUERY_SERVICE_ACCOUNT = os.environ.get("BIGQUERY_SERVICE_ACCOUNT")  # JSON string
credentials_info = json.loads(BIGQUERY_SERVICE_ACCOUNT)
credentials = service_account.Credentials.from_service_account_info(credentials_info)
bigquery_client = bigquery.Client(credentials=credentials)

# Firestore config
FIRESTORE_SERVICE_ACCOUNT = os.environ.get("FIRESTORE_SERVICE_ACCOUNT")  # JSON string
firestore_credentials_info = json.loads(FIRESTORE_SERVICE_ACCOUNT)
firestore_credentials = service_account.Credentials.from_service_account_info(firestore_credentials_info)
firestore_client = firestore.Client(credentials=firestore_credentials) 

# Database connection function
def get_db_connection():
    conn = psycopg2.connect(
        host=os.environ.get("DB_HOST"),
        port=os.environ.get("DB_PORT"),
        database=os.environ.get("DB_NAME"),
        user=os.environ.get("DB_USER"),
        password=os.environ.get("DB_PASS")
    )
    conn.autocommit = True
    return conn