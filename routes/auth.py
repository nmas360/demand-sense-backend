from flask import Blueprint
from utils.imports import *
from utils.config import *
from utils.decorators import *
from urllib.parse import quote

# Create the auth blueprint
auth_bp = Blueprint('auth', __name__)

@auth_bp.route("/auth/google")
def google_auth():
    # Check if we're in development mode and the dev_bypass parameter is provided
    if os.environ.get("REACT_APP_ENVIRONMENT", "").lower() == "development" and request.args.get("dev_bypass") == "true":
        return redirect(f"{FRONTEND_BASE_URL}/auth/dev-bypass")
        
    google = OAuth2Session(
        GOOGLE_CLIENT_ID,
        scope=SCOPE,
        redirect_uri=REDIRECT_URI
    )
    authorization_url, state = google.authorization_url(
        GOOGLE_AUTH_BASE_URL,
        access_type="offline",
        prompt="select_account"
    )
    # Instead of using session, set a cookie with the state
    response = redirect(authorization_url)
    response.set_cookie('oauth_state', state, httponly=True, secure=True, samesite='Lax', max_age=600)
    return response

@auth_bp.route("/auth/google/callback")
def google_callback():
    # Get state from cookie instead of session
    state = request.cookies.get('oauth_state')
    if not state:
        error_message = "No OAuth state found in cookies"
        return redirect(f"{FRONTEND_BASE_URL}?error={error_message}")
        
    google = OAuth2Session(
        GOOGLE_CLIENT_ID,
        redirect_uri=REDIRECT_URI,
        state=state
    )
    
    try:
        token = google.fetch_token(
            GOOGLE_TOKEN_URL,
            client_secret=GOOGLE_CLIENT_SECRET,
            authorization_response=request.url
        )
        resp = google.get("https://www.googleapis.com/oauth2/v2/userinfo")
        user_info = resp.json()

        user_email = user_info.get("email", "")
        user_name = user_info.get("name", "")
        
        # Check if user's email belongs to allowed domains
        email_domain = user_email.split('@')[-1]

        # Check if user has access to at least one project
        user_domain = "@" + email_domain
        projects_ref = firestore_client.collection('client_projects')
        
        # Check for domain-based access
        domain_projects = list(projects_ref.where('accessDomains', 'array_contains', user_domain).limit(1).stream())
        
        # Check for individual email access
        email_projects = list(projects_ref.where('accessEmails', 'array_contains', user_email).limit(1).stream())
        
        # If user is from s360digital.com, they get automatic access
        if email_domain == "s360digital.com":
            has_project_access = True
        else:
            # For other domains, check if user has access to at least one project
            has_project_access = len(domain_projects) > 0 or len(email_projects) > 0
        
        if not has_project_access:
            error_message = "You don't have access to any projects in the system"
            return redirect(f"{FRONTEND_BASE_URL}?error={error_message}")

        # Create user document in Firestore if it doesn't exist
        user_ref = firestore_client.collection('users').document(user_email)
        user_doc = user_ref.get()
        
        if not user_doc.exists:
            user_data = {
                'email': user_email,
                'name': user_name,
                'created_at': firestore.SERVER_TIMESTAMP,
                'last_login': firestore.SERVER_TIMESTAMP,
                'favorites': []  # Initialize empty favorites array
            }
            user_ref.set(user_data)
        else:
            # Update the last login timestamp
            user_ref.update({
                'last_login': firestore.SERVER_TIMESTAMP
            })

        # Use Copenhagen timezone for BigQuery timestamp
        copenhagen_tz = timezone('Europe/Copenhagen')
        copenhagen_time = datetime.now(copenhagen_tz)
        
        # Convert to timezone-naive datetime for BigQuery DATETIME field
        naive_datetime = copenhagen_time.replace(tzinfo=None)
        
        rows_to_insert = [{
            "date": naive_datetime.isoformat(sep=' '),  # Format as 'YYYY-MM-DD HH:MM:SS.ffffff'
            "mail": user_email,
            "name": user_name
        }]

        errors = bigquery_client.insert_rows_json("s360-demand-sensing.web_app_logs.web_app_logins", rows_to_insert)

        if errors:
            # Handle the insertion errors if any
            print(f"BigQuery insertion errors: {errors}")
            error_message = "Error inserting login record"
            return redirect(f"{FRONTEND_BASE_URL}?error={error_message}")

        # Store only the necessary OAuth token information
        oauth_token_data = {
            "access_token": token.get("access_token"),
            "refresh_token": token.get("refresh_token"),
            "token_type": token.get("token_type"),
            "expires_at": token.get("expires_at")
        }

        # Generate a JWT to pass to the frontend
        my_jwt = pyjwt.encode(
            {
                "email": user_email,
                "oauth_token": oauth_token_data,
                "exp": datetime.utcnow() + timedelta(hours=8)
            },
            os.environ.get("JWT_KEY"),
            algorithm="HS256"
        )

        # Redirect back to your frontend with the token and clear the oauth_state cookie
        response = redirect(f"{FRONTEND_BASE_URL}/auth/callback?token={my_jwt}")
        response.delete_cookie('oauth_state')
        return response
        
    except Exception as e:
        print(f"OAuth error: {str(e)}")
        error_message = f"Authentication error: {str(e)}"
        # URL encode the error message
        encoded_error = quote(error_message)
        return redirect(f"{FRONTEND_BASE_URL}?error={encoded_error}")

# Development-only route for bypassing Google auth
@auth_bp.route("/auth/dev-login", methods=["POST"])
def dev_login():
    # Only allow this in development mode
    if os.environ.get("REACT_APP_ENVIRONMENT", "").lower() != "development":
        return jsonify({"error": "This endpoint is only available in development mode"}), 403
        
    # Get email from request
    email = request.json.get("email", "dev@s360digital.com")
    name = request.json.get("name", "Development User")
    
    # Create a mock OAuth token
    mock_oauth_token = {
        "access_token": "dev-access-token",
        "refresh_token": "dev-refresh-token",
        "token_type": "Bearer",
        "expires_at": time.time() + 3600
    }
    
    # Generate JWT
    my_jwt = pyjwt.encode(
        {
            "email": email,
            "oauth_token": mock_oauth_token,
            "exp": datetime.utcnow() + timedelta(hours=8)
        },
        os.environ.get("JWT_KEY"),
        algorithm="HS256"
    )
    
    # Create or update user in Firestore
    try:
        user_ref = firestore_client.collection('users').document(email)
        user_doc = user_ref.get()
        
        if not user_doc.exists:
            user_data = {
                'email': email,
                'name': name,
                'created_at': firestore.SERVER_TIMESTAMP,
                'last_login': firestore.SERVER_TIMESTAMP,
                'favorites': []
            }
            if "s360digital.com" in email:
                user_data['admin'] = True
                
            user_ref.set(user_data)
        else:
            user_ref.update({
                'last_login': firestore.SERVER_TIMESTAMP
            })
    except Exception as e:
        print(f"Firestore error in dev mode: {str(e)}")
    
    return jsonify({"token": my_jwt}) 


@auth_bp.route("/api/user/admin/status", methods=["GET"])
@token_required
def check_admin_status(current_user):
    try:
        # Get user document from Firestore
        user_ref = firestore_client.collection('users').document(current_user)
        user_doc = user_ref.get()
        
        if not user_doc.exists:
            return jsonify({"isAdmin": False}), 200
            
        # Check if the user is an admin
        user_data = user_doc.to_dict()
        is_admin = user_data.get('admin', False)
        
        return jsonify({"isAdmin": is_admin}), 200
    except Exception as e:
        print(f"Error checking admin status: {str(e)}")
        return jsonify({"error": f"Failed to check admin status: {str(e)}"}), 500
