import os
import json
import jwt as pyjwt
import uuid
import re
from flask import Flask, request, jsonify, send_file, session, redirect, url_for, Response, g, make_response
from datetime import datetime, timedelta
from dotenv import load_dotenv
from flask_cors import CORS
from google.cloud import storage, bigquery, firestore
from google.oauth2 import service_account
from requests_oauthlib import OAuth2Session
from functools import wraps
from googleapiclient.discovery import build
import google.oauth2.credentials
from pytz import timezone
import googleapiclient.discovery
from google.api_core.exceptions import PermissionDenied, NotFound
from google.cloud import bigquery_datatransfer_v1
import logging
import time
import psycopg2
import psycopg2.extras
import pandas as pd
import numpy as np
from concurrent.futures import ThreadPoolExecutor, as_completed
import traceback
import random
from queue import Queue
import threading


# Set environment variable to allow OAuth to work over HTTP (only for development)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = os.environ.get("OAUTHLIB_INSECURE_TRANSPORT")

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("JWT_KEY")  # for session

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
GOOGLE_AUTH_BASE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"

# Scope includes user's email, profile, and Google Sheets access
SCOPE = [
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/drive.file",
]

REDIRECT_URI = os.environ.get("GOOGLE_REDIRECT_URI")
FRONTEND_BASE_URL = os.environ.get("FRONTEND_BASE_URL")

CORS(app)  # This enables CORS for all routes



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


# Authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Check if the token is in the headers
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'error': 'Token is missing!'}), 401
        
        try:
            # Decode the token
            data = pyjwt.decode(token, os.environ.get("JWT_KEY"), algorithms=["HS256"])
            current_user = data['email']
        except:
            return jsonify({'error': 'Token is invalid!'}), 401
            
        return f(current_user, *args, **kwargs)
    
    return decorated

# Decorator to check project access
def project_access_required(f):
    """
    Decorator to check if user has access to a project.
    This decorator should be used after @token_required.
    
    It will:
    1. Extract project_id from request arguments
    2. Check if user has access to the project
    3. Add cloud_project_id to kwargs if access is granted
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # The first arg should be current_user from @token_required
        current_user = args[0]
        
        cloud_project_id = None
        
        # Get project_id from request arguments
        project_id = request.args.get('project_id', None)
        
        # If no project_id provided, skip access check
        if project_id:
            # Get project data from Firestore
            project_ref = firestore_client.collection('client_projects').document(project_id)
            project_doc = project_ref.get()
            
            # Check if project exists
            if not project_doc.exists:
                return jsonify({"error": "Project not found"}), 404
            
            # Get project data
            project_data = project_doc.to_dict()
            cloud_project_id = project_data.get('cloudProjectId')
            
            # Check if user has access to this project
            user_domain = "@" + current_user.split('@')[1]
            user_has_access = False
            
            # Check domain access
            if "accessDomains" in project_data and isinstance(project_data["accessDomains"], list):
                if user_domain in project_data["accessDomains"]:
                    user_has_access = True
            
            # Check individual email access
            if not user_has_access and "accessEmails" in project_data and isinstance(project_data["accessEmails"], list):
                if current_user in project_data["accessEmails"]:
                    user_has_access = True
            
            # Access denied if user doesn't have access to the project
            if not user_has_access:
                return jsonify({"error": "You don't have access to this project"}), 403
            
        # Add cloud_project_id to kwargs
        kwargs['cloud_project_id'] = cloud_project_id
        
        # Call the original function with the added kwargs
        return f(*args, **kwargs)
    
    return decorated

def token_required_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Check if the token is in the headers
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'error': 'Token is missing!'}), 401
        
        try:
            # Decode the token
            data = pyjwt.decode(token, os.environ.get("JWT_KEY"), algorithms=["HS256"])
            current_user = data['email']
            
            # Check if the user is an admin
            user_ref = firestore_client.collection('users').document(current_user)
            user_doc = user_ref.get()
            
            if not user_doc.exists:
                return jsonify({'error': 'User not found!'}), 404
                
            # Check if the user is an admin
            user_data = user_doc.to_dict()
            is_admin = user_data.get('admin', False)
            
            if not is_admin:
                return jsonify({'error': 'Admin privileges required!'}), 403
                
        except Exception as e:
            return jsonify({'error': f'Authentication error: {str(e)}'}), 401
            
        return f(current_user, *args, **kwargs)
    
    return decorated

### AUTHENTICATION ROUTES ###
@app.route("/auth/google")
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

@app.route("/auth/google/callback")
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
        from urllib.parse import quote
        encoded_error = quote(error_message)
        return redirect(f"{FRONTEND_BASE_URL}?error={encoded_error}")

# Development-only route for bypassing Google auth
@app.route("/auth/dev-login", methods=["POST"])
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

### PROTECTED ROUTES ###
@app.route("/api/user/admin/status", methods=["GET"])
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


@app.route("/api/popular_products", methods=["GET"])
@token_required
@project_access_required
def get_popular_products(current_user, cloud_project_id = None):
    try:
        # Get query parameters for filtering
        date_filter = request.args.get('date', None)
        dates = request.args.getlist('dates[]')  # Get multiple dates as array
        
        # Get time period mode for multi-month selection
        time_period_mode = request.args.get('time_period_mode', 'strict')  # Default to strict mode
        
        # Brand filter parameters
        brand_filter = request.args.get('brand', None)
        brands = request.args.getlist('brands[]')  # Get multiple brands as array
        
        # Category filter parameters
        category_filter = request.args.get('category', None)
        categories = request.args.getlist('categories[]')  # Get multiple categories as array
        
        # Title filter parameter
        title_filter = request.args.get('title_filter', None)
        
        # Get countries and merchant center ID
        countries = request.args.getlist('countries[]')  # Get country filters - keeping for backward compatibility
        original_codes = request.args.getlist('original_codes[]')  # Get original country codes for the products CTE
        mapped_markets = request.args.getlist('mapped_markets[]')  # Get mapped markets for the bestseller filtering

        merchant_center_id = request.args.get('merchant_center_id', None)  # Get merchant center ID for country
        
        # Get inventory status filters - now mapped to in_assortment values
        inventory_statuses = request.args.getlist('inventory_statuses[]')
        
        # Get pagination parameters
        limit = request.args.get('limit', 20, type=int)
        offset = request.args.get('offset', 0, type=int)
        
        # Get sorting parameters
        sort_column = request.args.get('sort_column', 'avg_rank')
        sort_direction = request.args.get('sort_direction', 'asc').upper()
        
        # Initialize variables for query
        products = []
        total_count = 0
        unique_brands_count = 0
        filtered_favorites_count = 0
        
        # Only proceed if we have at least one date and country
        if (date_filter or dates) and countries and len(countries) > 0:
            # Build the date filter part of the query
            date_filter_clause = ""
            if dates and len(dates) > 0:
                date_strings = [f"'{date}'" for date in dates]
                date_filter_clause = f"date_month IN ({', '.join(date_strings)})"
            elif date_filter:
                date_filter_clause = f"date_month = '{date_filter}'"
            
            # Build the country filter part of the query for bestseller data
            country_filter_clause = ""
            if mapped_markets and len(mapped_markets) > 0:
                # Use mapped markets for bestseller filtering
                country_strings = [f"'{country}'" for country in mapped_markets]
                country_filter_clause = f"country_code IN ({', '.join(country_strings)})"
            elif countries and len(countries) > 0:
                # Fall back to original countries for backward compatibility
                country_strings = [f"'{country}'" for country in countries]
                country_filter_clause = f"country_code IN ({', '.join(country_strings)})"
            
            # Build the brand filter part of the query
            brand_filter_clause = ""
            if brands and len(brands) > 0:
                brand_strings = [f"'{brand}'" for brand in brands]
                brand_filter_clause = f"brand IN ({', '.join(brand_strings)})"
            elif brand_filter:
                brand_filter_clause = f"brand = '{brand_filter}'"
            else:
                brand_filter_clause = "1=1"  # Always true if no brand filter
            
            # Build the category filter part of the query
            category_filter_clause = ""
            if categories and len(categories) > 0:
                category_strings = [f"'{category}'" for category in categories]
                category_filter_clause = f"category IN ({', '.join(category_strings)})"
            elif category_filter:
                category_filter_clause = f"category = '{category_filter}'"
            
            # Add new filters for category_l2 and category_l3
            category_l2_filter_clause = ""
            categories_l2 = request.args.getlist('categories_l2[]')
            if categories_l2 and len(categories_l2) > 0:
                category_l2_strings = [f"'{category}'" for category in categories_l2]
                category_l2_filter_clause = f"category_l2 IN ({', '.join(category_l2_strings)})"
            
            category_l3_filter_clause = ""
            categories_l3 = request.args.getlist('categories_l3[]')
            if categories_l3 and len(categories_l3) > 0:
                category_l3_strings = [f"'{category}'" for category in categories_l3]
                category_l3_filter_clause = f"category_l3 IN ({', '.join(category_l3_strings)})"
            
            # Combine category filters
            filter_clauses = []
            if category_filter_clause:
                filter_clauses.append(category_filter_clause)
            if category_l2_filter_clause:
                filter_clauses.append(category_l2_filter_clause)
            if category_l3_filter_clause:
                filter_clauses.append(category_l3_filter_clause)
                
            # If no category filters are present, use a default true condition
            if not filter_clauses:
                combined_category_filter = "1=1"
            else:
                combined_category_filter = "(" + " OR ".join(filter_clauses) + ")"
            
            # Build the title filter part of the query
            title_filter_clause = ""
            if title_filter:
                # Escape single quotes in the title filter to prevent SQL injection
                safe_title_filter = title_filter.replace("'", "''")
                # Use LOWER() on both sides for case-insensitive matching
                title_filter_clause = f"LOWER(title) LIKE LOWER('%{safe_title_filter}%')"
            else:
                title_filter_clause = "1=1"  # Always true if no title filter
            
            # Determine which country codes to use for products filtering
            products_country_codes = original_codes if original_codes and len(original_codes) > 0 else countries
            
            # Construct the SQL query with the correct merchant center ID
            # For multiple dates, we need to handle the time_period_mode differently
            if dates and len(dates) > 1:
                # For multiple dates, we need to modify the query based on time_period_mode
                if time_period_mode == 'strict':
                    # "All Months" mode - products must appear in all selected months
                    # We need to count the number of distinct months a product appears in
                    query = f"""
                    WITH months_data AS (
                      SELECT DISTINCT
                        entity_id,
                        title,
                        country_code,
                        brand,
                        category,
                        category_l2,
                        category_l3,
                        report_category_id,
                        COUNT(DISTINCT date_month) AS month_count,
                        AVG(SAFE_CAST(rank AS FLOAT64)) AS avg_rank
                      FROM `s360-demand-sensing.ds_master_transformed_data.bestseller_monthly`
                      WHERE {date_filter_clause}
                      AND {country_filter_clause}
                      AND {brand_filter_clause}
                      AND {combined_category_filter}
                      AND {title_filter_clause}
                      GROUP BY entity_id, title, country_code, brand, category, category_l2, category_l3, report_category_id
                      HAVING COUNT(DISTINCT date_month) = {len(dates)}
                    ),
                    products AS (
                      SELECT DISTINCT
                        product_id
                      FROM `{cloud_project_id}.ds_raw_data.Products_{merchant_center_id}`
                      WHERE _PARTITIONTIME = (
                        SELECT MAX(_PARTITIONTIME)
                        FROM `{cloud_project_id}.ds_raw_data.Products_{merchant_center_id}`
                      )
                      AND channel = 'online'
                      AND feed_label IN ({', '.join([f"'{country}'" for country in products_country_codes])})
                    ),
                    mapping AS (
                      SELECT DISTINCT
                        m.entity_id,
                        m.product_id
                      FROM `{cloud_project_id}.ds_raw_data.BestSellersEntityProductMapping_{merchant_center_id}` AS m
                    ),
                    final_data AS (
                      SELECT DISTINCT
                        months_data.report_category_id,
                        months_data.category,
                        months_data.category_l2,
                        months_data.category_l3,
                        months_data.entity_id,
                        months_data.title,
                        months_data.country_code,
                        months_data.brand,
                        (SELECT MIN(date_month) FROM `s360-demand-sensing.ds_master_transformed_data.bestseller_monthly` 
                         WHERE entity_id = months_data.entity_id 
                         AND {date_filter_clause}) AS date_month,
                        months_data.avg_rank,
                        CASE 
                          WHEN products.product_id IS NOT NULL THEN 1
                          ELSE 0
                        END AS in_assortment
                      FROM months_data
                      LEFT JOIN mapping 
                      ON months_data.entity_id = mapping.entity_id
                      LEFT JOIN products 
                      ON mapping.product_id = products.product_id
                    )
                    """
                else:
                    # "Any Month" mode - products must appear in at least one of the selected months
                    query = f"""
                    WITH months_data AS (
                      SELECT DISTINCT
                        entity_id,
                        title,
                        country_code,
                        brand,
                        category,
                        category_l2,
                        category_l3,
                        report_category_id,
                        AVG(SAFE_CAST(rank AS FLOAT64)) AS avg_rank
                      FROM `s360-demand-sensing.ds_master_transformed_data.bestseller_monthly`
                      WHERE {date_filter_clause}
                      AND {country_filter_clause}
                      AND {brand_filter_clause}
                      AND {combined_category_filter}
                      AND {title_filter_clause}
                      GROUP BY entity_id, title, country_code, brand, category, category_l2, category_l3, report_category_id
                    ),
                    products AS (
                      SELECT DISTINCT
                        product_id
                      FROM `{cloud_project_id}.ds_raw_data.Products_{merchant_center_id}`
                      WHERE _PARTITIONTIME = (
                        SELECT MAX(_PARTITIONTIME)
                        FROM `{cloud_project_id}.ds_raw_data.Products_{merchant_center_id}`
                      )
                      AND channel = 'online'
                      AND feed_label IN ({', '.join([f"'{country}'" for country in products_country_codes])})
                    ),
                    mapping AS (
                      SELECT DISTINCT
                        m.entity_id,
                        m.product_id
                      FROM `{cloud_project_id}.ds_raw_data.BestSellersEntityProductMapping_{merchant_center_id}` AS m
                    ),
                    final_data AS (
                      SELECT
                        months_data.report_category_id,
                        months_data.category,
                        months_data.category_l2,
                        months_data.category_l3,
                        months_data.entity_id,
                        months_data.title,
                        months_data.country_code,
                        months_data.brand,
                        (SELECT MIN(date_month) FROM `s360-demand-sensing.ds_master_transformed_data.bestseller_monthly` 
                         WHERE entity_id = months_data.entity_id 
                         AND {date_filter_clause}) AS date_month,
                        months_data.avg_rank,
                        CASE 
                          WHEN products.product_id IS NOT NULL THEN 1
                          ELSE 0
                        END AS in_assortment
                      FROM months_data
                      LEFT JOIN mapping 
                      ON months_data.entity_id = mapping.entity_id
                      LEFT JOIN products 
                      ON mapping.product_id = products.product_id
                    )
                    """
            else:
                # Single date/month selection or default behavior
                query = f"""
                WITH main_bestseller AS (
                  SELECT DISTINCT
                    report_category_id,
                    category,
                    category_l2,
                    category_l3,
                    entity_id,
                    title,
                    country_code,
                    brand,
                    date_month,
                    rank AS avg_rank
                  FROM `s360-demand-sensing.ds_master_transformed_data.bestseller_monthly`
                  WHERE {date_filter_clause}
                  AND {country_filter_clause}
                  AND {brand_filter_clause}
                  AND {combined_category_filter}
                  AND {title_filter_clause}
                ),
                products AS (
                  SELECT DISTINCT
                    product_id
                  FROM `{cloud_project_id}.ds_raw_data.Products_{merchant_center_id}`
                  WHERE _PARTITIONTIME = (
                    SELECT MAX(_PARTITIONTIME)
                    FROM `{cloud_project_id}.ds_raw_data.Products_{merchant_center_id}`
                  )
                  AND channel = 'online'
                  AND feed_label IN ({', '.join([f"'{country}'" for country in products_country_codes])})
                ),
                mapping AS (
                  SELECT DISTINCT
                    m.entity_id,
                    m.product_id
                  FROM `{cloud_project_id}.ds_raw_data.BestSellersEntityProductMapping_{merchant_center_id}` AS m
                ),
                final_data AS (
                  SELECT DISTINCT
                    main_bestseller.report_category_id,
                    main_bestseller.category,
                    main_bestseller.category_l2,
                    main_bestseller.category_l3,
                    main_bestseller.entity_id,
                    main_bestseller.title,
                    main_bestseller.country_code,
                    main_bestseller.brand,
                    main_bestseller.date_month,
                    main_bestseller.avg_rank,
                    CASE 
                      WHEN products.product_id IS NOT NULL THEN 1
                      ELSE 0
                    END AS in_assortment
                  FROM main_bestseller
                  LEFT JOIN mapping 
                  ON main_bestseller.entity_id = mapping.entity_id
                  LEFT JOIN products 
                  ON mapping.product_id = products.product_id
                )
                """

            # Add inventory status filter if provided, mapping it to in_assortment
            query += "\nSELECT DISTINCT report_category_id, category, category_l2, category_l3, entity_id, title, country_code, brand, date_month, avg_rank, in_assortment FROM final_data"
            
            # Apply inventory status filter to main query if provided, translating to in_assortment
            if inventory_statuses and len(inventory_statuses) > 0:
                # Map the old inventory statuses to new in_assortment values
                # 'IN_STOCK' -> in_assortment = 1
                # 'NOT_IN_INVENTORY' -> in_assortment = 0
                in_assortment_values = []
                for status in inventory_statuses:
                    if status == 'IN_STOCK':
                        in_assortment_values.append('1')
                    elif status == 'NOT_IN_INVENTORY':
                        in_assortment_values.append('0')
                
                if in_assortment_values:
                    query += f"\nWHERE in_assortment IN ({', '.join(in_assortment_values)})"
            
            # Add ordering and pagination
            # If sort_column is product_inventory_status, we need to change it to in_assortment
            if sort_column == "product_inventory_status":
                sort_column = "in_assortment"
                
            query += f"\nORDER BY {sort_column} {sort_direction}"
            query += f"\nLIMIT {limit} OFFSET {offset}"

            # Count query for pagination and stats - need to modify for multi-date selection
            if dates and len(dates) > 1:
                # For multiple dates, we need to adjust the count query based on time_period_mode
                if time_period_mode == 'strict':
                    count_query = f"""
                    WITH months_count AS (
                      SELECT
                        entity_id,
                        country_code,
                        brand,
                        COUNT(DISTINCT date_month) AS month_count
                      FROM `s360-demand-sensing.ds_master_transformed_data.bestseller_monthly`
                      WHERE {date_filter_clause}
                      AND {country_filter_clause}
                      AND {brand_filter_clause}
                      AND {combined_category_filter}
                      AND {title_filter_clause}
                      GROUP BY entity_id, country_code, brand
                      HAVING COUNT(DISTINCT date_month) = {len(dates)} 
                    ),
                    products AS (
                      SELECT DISTINCT
                        product_id
                      FROM `{cloud_project_id}.ds_raw_data.Products_{merchant_center_id}`
                      WHERE _PARTITIONTIME = (
                        SELECT MAX(_PARTITIONTIME)
                        FROM `{cloud_project_id}.ds_raw_data.Products_{merchant_center_id}`
                      )
                      AND channel = 'online'
                      AND feed_label IN ({', '.join([f"'{country}'" for country in products_country_codes])})
                    ),
                    mapping AS (
                      SELECT DISTINCT
                        m.entity_id,
                        m.product_id
                      FROM `{cloud_project_id}.ds_raw_data.BestSellersEntityProductMapping_{merchant_center_id}` AS m
                    ),
                    final_count AS (
                      SELECT
                        months_count.entity_id,
                        months_count.brand,
                        CASE 
                          WHEN products.product_id IS NOT NULL THEN 1
                          ELSE 0
                        END AS in_assortment
                      FROM months_count
                      LEFT JOIN mapping 
                      ON months_count.entity_id = mapping.entity_id
                      LEFT JOIN products 
                      ON mapping.product_id = products.product_id
                    )
                    """
                else:
                    # "Any Month" mode - count products that appear in at least one selected month
                    count_query = f"""
                    WITH months_count AS (
                      SELECT
                        entity_id,
                        country_code,
                        brand
                      FROM `s360-demand-sensing.ds_master_transformed_data.bestseller_monthly`
                      WHERE {date_filter_clause}
                      AND {country_filter_clause}
                      AND {brand_filter_clause}
                      AND {combined_category_filter}
                      AND {title_filter_clause}
                      GROUP BY entity_id, country_code, brand
                    ),
                    products AS (
                      SELECT DISTINCT
                        product_id
                      FROM `{cloud_project_id}.ds_raw_data.Products_{merchant_center_id}`
                      WHERE _PARTITIONTIME = (
                        SELECT MAX(_PARTITIONTIME)
                        FROM `{cloud_project_id}.ds_raw_data.Products_{merchant_center_id}`
                      )
                      AND channel = 'online'
                      AND feed_label IN ({', '.join([f"'{country}'" for country in products_country_codes])})
                    ),
                    mapping AS (
                      SELECT DISTINCT
                        m.entity_id,
                        m.product_id
                      FROM `{cloud_project_id}.ds_raw_data.BestSellersEntityProductMapping_{merchant_center_id}` AS m
                    ),
                    final_count AS (
                      SELECT
                        months_count.entity_id,
                        months_count.brand,
                        CASE 
                          WHEN products.product_id IS NOT NULL THEN 1
                          ELSE 0
                        END AS in_assortment
                      FROM months_count
                      LEFT JOIN mapping 
                      ON months_count.entity_id = mapping.entity_id
                      LEFT JOIN products 
                      ON mapping.product_id = products.product_id
                    )
                    """
            else:
                # Original count query for single date selection
                count_query = f"""
                WITH main_bestseller AS (
                  SELECT
                    entity_id,
                    country_code,
                    brand,
                    title,
                    date_month
                  FROM `s360-demand-sensing.ds_master_transformed_data.bestseller_monthly`
                  WHERE {date_filter_clause}
                  AND {country_filter_clause}
                  AND {brand_filter_clause}
                  AND {combined_category_filter}
                  AND {title_filter_clause}
                ),
                products AS (
                  SELECT DISTINCT
                    product_id
                  FROM `{cloud_project_id}.ds_raw_data.Products_{merchant_center_id}`
                  WHERE _PARTITIONTIME = (
                    SELECT MAX(_PARTITIONTIME)
                    FROM `{cloud_project_id}.ds_raw_data.Products_{merchant_center_id}`
                  )
                  AND channel = 'online'
                  AND feed_label IN ({', '.join([f"'{country}'" for country in products_country_codes])})
                ),
                mapping AS (
                  SELECT DISTINCT
                    m.entity_id,
                    m.product_id
                  FROM `{cloud_project_id}.ds_raw_data.BestSellersEntityProductMapping_{merchant_center_id}` AS m
                ),
                final_count AS (
                  SELECT
                    main_bestseller.entity_id,
                    main_bestseller.brand,
                    CASE 
                      WHEN products.product_id IS NOT NULL THEN 1
                      ELSE 0
                    END AS in_assortment
                  FROM main_bestseller
                  LEFT JOIN mapping 
                  ON main_bestseller.entity_id = mapping.entity_id
                  LEFT JOIN products 
                  ON mapping.product_id = products.product_id
                )
                """

            # Complete and execute the count query
            count_query += """
            SELECT
              COUNT(DISTINCT entity_id) as total_count,
              COUNT(DISTINCT brand) as unique_brands_count
            FROM final_count
            """

            # Add inventory status filter to count query if provided
            if inventory_statuses and len(inventory_statuses) > 0:
                # Map the old inventory statuses to new in_assortment values
                in_assortment_values = []
                for status in inventory_statuses:
                    if status == 'IN_STOCK':
                        in_assortment_values.append('1')
                    elif status == 'NOT_IN_INVENTORY':
                        in_assortment_values.append('0')
                
                if in_assortment_values:
                    count_query += f"\nWHERE in_assortment IN ({', '.join(in_assortment_values)})"
            
            # Execute both queries in parallel using ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=2) as executor:
                products_future = executor.submit(bigquery_client.query, query)
                count_future = executor.submit(bigquery_client.query, count_query)
                
                # Wait for both queries to complete and get results
                products_job = products_future.result()
                count_job = count_future.result()
            
            # Convert products results to list of dictionaries
            for row in products_job.result():
                # Create a product dictionary with backward compatibility for product_inventory_status
                product = {
                    "report_category_id": row.report_category_id,
                    "category": row.category,
                    "category_l2": row.category_l2,
                    "category_l3": row.category_l3,
                    "entity_id": row.entity_id,
                    "title": row.title,
                    "country_code": row.country_code,
                    "brand": row.brand,
                    "date_month": row.date_month.isoformat() if row.date_month else None,
                    "avg_rank": row.avg_rank,
                    "in_assortment": row.in_assortment,
                    # Keep product_inventory_status for backward compatibility
                    "product_inventory_status": "IN_STOCK" if row.in_assortment == 1 else "NOT_IN_INVENTORY"
                }
                products.append(product)
            
            # Extract count information
            total_count = 0
            unique_brands_count = 0
            for row in count_job.result():
                total_count = row.total_count
                unique_brands_count = row.unique_brands_count
                break  # Only need the first row


        return jsonify({
            "products": products, 
            "count": len(products),
            "total": total_count,
            "page": offset // limit + 1,
            "pages": (total_count + limit - 1) // limit,
            "stats": {
                "total_products": total_count,
                "unique_brands": unique_brands_count,
                "filtered_favorites": filtered_favorites_count
            }
        })
        
    except Exception as e:
        print(f"Error querying BigQuery: {str(e)}")
        return jsonify({"error": f"Failed to fetch popular products: {str(e)}"}), 500 

@app.route("/api/categories", methods=["GET"])
@token_required
@project_access_required
def get_categories(current_user, cloud_project_id=None):
    try:
        # Get request parameters
        country = request.args.get('country')  # Keep for backward compatibility
        merchant_center_id = request.args.get('merchant_center_id')
        
        # Get new parameters for mapped market and original code
        mapped_market = request.args.get('mapped_market')  # For bestseller filtering
        original_code = request.args.get('original_code')  # For products filtering
        
        # Add debug logging for parameter values
        print(f"DEBUG: Parameters received - mapped_market: {mapped_market}, original_code: {original_code}, country: {country}")
        
        # Get date parameters if they exist (for bestseller filtering)
        date_filter = request.args.get('date', None)
        dates = request.args.getlist('dates[]')  # Get multiple dates as array

        # Get project_id parameter
        master_project_id = "s360-demand-sensing"

        # If we have cloud_project_id and merchant_center_id, use the enhanced query
        if cloud_project_id and merchant_center_id:
            # Build date filter clause for bestseller data
            date_filter_clause = ""
            if dates and len(dates) > 0:
                date_strings = [f"'{date}'" for date in dates]
                date_filter_clause = f"AND date_month IN ({', '.join(date_strings)})"
            elif date_filter:
                date_filter_clause = f"AND date_month = '{date_filter}'"
            
            # Build country filter clause for bestseller data - use mapped_market if available
            country_filter_clause = ""
            if mapped_market:
                country_filter_clause = f"AND country_code = '{mapped_market}'"
                print(f"DEBUG: Using mapped_market for bestseller filtering: {mapped_market}")
            elif country:
                country_filter_clause = f"AND country_code = '{country}'"
                print(f"DEBUG: Using country for bestseller filtering (fallback): {country}")
            
            # Determine which country code to use for products filtering - use original_code if available
            products_country_code = original_code if original_code else (country if country else "")
            print(f"DEBUG: Using products_country_code for products filtering: {products_country_code}")
            
            if not products_country_code:
                return jsonify({"error": "Missing country parameter"}), 400

            query = f"""
            WITH products AS (
              SELECT DISTINCT
                offer_id,
                product_id
              FROM `{cloud_project_id}.ds_raw_data.Products_{merchant_center_id}`
              WHERE _PARTITIONTIME = (SELECT MAX(_PARTITIONTIME) FROM `{cloud_project_id}.ds_raw_data.Products_{merchant_center_id}`)
              AND channel = 'online'
              AND LOWER(feed_label) = '{products_country_code.lower()}'
            ),

            bestseller_main AS (
              SELECT DISTINCT
                category,
                entity_id,
                title
              FROM `{master_project_id}.ds_master_transformed_data.bestseller_monthly`
              WHERE 1=1 {date_filter_clause} {country_filter_clause}
            ),

            mapping AS (
              SELECT DISTINCT
                m.entity_id,
                m.product_id,
                bm.category,
                bm.title
              FROM `{cloud_project_id}.ds_raw_data.BestSellersEntityProductMapping_{merchant_center_id}` AS m
              LEFT JOIN bestseller_main AS bm
              ON bm.entity_id = m.entity_id
            ),

            final AS (
              SELECT
                m.entity_id,
                m.category,
                m.title,
                CASE WHEN p.product_id IS NOT NULL THEN 1 ELSE 0 END AS in_assortment
              FROM mapping AS m
              LEFT JOIN products AS p
              ON m.product_id = p.product_id
              WHERE m.entity_id IS NOT NULL
            ),
            
            category_counts AS (
              SELECT
                category AS level_1,
                COUNT(DISTINCT entity_id) AS total_entities,
                COUNT(DISTINCT title) AS total_products,
                SUM(CASE WHEN in_assortment = 1 THEN 1 ELSE 0 END) AS in_assortment_entity_count,
                COUNT(DISTINCT CASE WHEN in_assortment = 1 THEN title ELSE NULL END) AS in_assortment_count
              FROM final
              WHERE category IS NOT NULL
              GROUP BY 1
              ORDER BY 2 DESC
            )
            
            SELECT DISTINCT
                t.google_cat_id,
                t.level_1,
                COALESCE(c.total_products, 0) AS total_products,
                COALESCE(c.in_assortment_count, 0) AS in_assortment_count,
                COALESCE(c.total_entities, 0) AS total_entities,
                COALESCE(c.in_assortment_entity_count, 0) AS in_assortment_entity_count
            FROM `{master_project_id}.ds_master_transformed_data.google_taxonomy` AS t
            LEFT JOIN category_counts AS c
            ON t.level_1 = c.level_1
            ORDER BY total_products DESC, t.level_1 ASC
            """
        else:
            # Fallback to original query if missing cloud_project_id or merchant_center_id
            query = f"""
            SELECT 
                google_cat_id, 
                level_1,
                0 AS total_products,
                0 AS in_assortment_count,
                0 AS total_entities,
                0 AS in_assortment_entity_count
            FROM `{master_project_id}.ds_master_transformed_data.google_taxonomy`
            """
        
        # Execute the query
        query_job = bigquery_client.query(query)
        results = query_job.result()
        
        # Convert to dictionary for easy lookup of id->name
        categories = {}
        # Create dictionaries to store category counts
        category_counts = {}
        category_in_assortment_counts = {}
        
        # Add new dictionaries for entity counts
        category_entity_counts = {}
        category_in_assortment_entity_counts = {}
        
        for row in results:
            # Store keys as integers instead of strings
            categories[row.google_cat_id] = row.level_1
            
            # Store the total count for each category name
            if row.level_1 not in category_counts or (row.total_products > category_counts[row.level_1]):
                category_counts[row.level_1] = row.total_products
            
            # Store the in_assortment count for each category
            if row.level_1 not in category_in_assortment_counts or (row.in_assortment_count > category_in_assortment_counts[row.level_1]):
                category_in_assortment_counts[row.level_1] = row.in_assortment_count
                
            # Store entity counts for comparison
            if row.level_1 not in category_entity_counts or (row.total_entities > category_entity_counts[row.level_1]):
                category_entity_counts[row.level_1] = row.total_entities
                
            if row.level_1 not in category_in_assortment_entity_counts or (row.in_assortment_entity_count > category_in_assortment_entity_counts[row.level_1]):
                category_in_assortment_entity_counts[row.level_1] = row.in_assortment_entity_count
        
        # Create a list of unique level_1 category names for filtering
        distinct_categories = list(set(categories.values()))
        # Sort by product count descending, then alphabetically
        distinct_categories.sort(key=lambda x: (-category_counts.get(x, 0), x))
        
        # Group category IDs by level_1 name
        categories_grouped = {}
        for cat_id, level_1 in categories.items():
            if level_1 not in categories_grouped:
                categories_grouped[level_1] = []
            categories_grouped[level_1].append(cat_id)

        return jsonify({
            "categories": categories,
            "distinct_categories": distinct_categories,
            "categories_grouped": categories_grouped,
            "category_counts": category_counts,
            "category_in_assortment_counts": category_in_assortment_counts,
            "category_entity_counts": category_entity_counts,
            "category_in_assortment_entity_counts": category_in_assortment_entity_counts
        })
    except Exception as e:
        print(f"Error fetching categories: {str(e)}")
        return jsonify({"error": f"Failed to fetch categories: {str(e)}"}), 500 

@app.route("/api/complete_category_hierarchy", methods=["GET"])
@token_required
@project_access_required
def get_complete_category_hierarchy(current_user, cloud_project_id=None):
    """Get a complete hierarchical structure of all categories"""
    try:
        # Get project ID
        project_id = request.args.get('project_id')
        if not project_id:
            return jsonify({"error": "Missing project_id parameter"}), 400
            
        # Get merchant center ID
        merchant_center_id = None
        
        # Try to find a merchant center from the project
        project_ref = firestore_client.collection('client_projects').document(project_id)
        project_doc = project_ref.get()
        
        if project_doc.exists:
            project_data = project_doc.to_dict()
            if project_data and project_data.get('merchantCenters') and len(project_data['merchantCenters']) > 0:
                # Get first merchant center ID available
                merchant_center_id = project_data['merchantCenters'][0].get('merchantCenterId')
        
        # Build the query to get the complete hierarchy
        master_project_id = "s360-demand-sensing"
        
        # Use the merchant center ID if available
        if cloud_project_id and merchant_center_id:
            query = f"""
            SELECT 
            level_1,
            level_2,
            level_3
            FROM `s360-demand-sensing.ds_master_transformed_data.google_taxonomy` 
            """
            
        # Execute the query
        query_job = bigquery_client.query(query)
        results = query_job.result()
        
        # Build the hierarchical structure
        hierarchy = {}
        
        for row in results:
            level_1 = row.level_1
            level_2 = row.level_2
            level_3 = row.level_3
            
            # Add level 1 if not exists
            if level_1 not in hierarchy:
                hierarchy[level_1] = {}
                
            # Add level 2 if it exists and not already added
            if level_2 and level_2 not in hierarchy[level_1]:
                hierarchy[level_1][level_2] = {}
                
            # Add level 3 if it exists
            if level_2 and level_3:
                hierarchy[level_1][level_2][level_3] = True
        
        return jsonify({
            "success": True,
            "hierarchy": hierarchy
        })
        
    except Exception as e:
        print(f"Error fetching complete category hierarchy: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Failed to fetch complete category hierarchy: {str(e)}"
        }), 500

@app.route("/api/brands", methods=["GET"])
@token_required
def get_distinct_brands(current_user):
    try:
        # Get project_id parameter
        master_project_id = "s360-demand-sensing"
        
        # Get search parameter if provided
        search_term = request.args.get('search', '')
        
        # Modify query based on whether we have a search term
        if search_term and len(search_term) >= 3:
            # If search term provided, filter brands in the query
            query = f"""
            SELECT brand 
            FROM (
                SELECT 
                brand,
                MIN(rank) AS min_rank
                FROM `{master_project_id}.ds_master_transformed_data.bestseller_monthly`
                WHERE brand IS NOT NULL
                AND LOWER(brand) LIKE LOWER('%{search_term}%')
                GROUP BY brand
            )
            ORDER BY min_rank
            LIMIT 200
            """
        else:
            # If no search term or too short, return top brands only
            query = f"""
            SELECT brand 
            FROM (
                SELECT 
                brand,
                MIN(rank) AS min_rank
                FROM `{master_project_id}.ds_master_transformed_data.bestseller_monthly`
                WHERE brand IS NOT NULL
                GROUP BY brand
            )
            ORDER BY min_rank
            LIMIT 200
            """
        
        # Execute the query
        query_job = bigquery_client.query(query)
        results = query_job.result()
        
        # Convert to list
        brands = [row.brand for row in results]
        
        return jsonify({"brands": brands})
    except Exception as e:
        print(f"Error fetching brands: {str(e)}")
        return jsonify({"error": f"Failed to fetch brands: {str(e)}"}), 500

@app.route("/api/countries", methods=["GET"])
@token_required
def get_distinct_countries(current_user, cloud_project_id = None):
    try:
        # Get project_id parameter
        master_project_id = "s360-demand-sensing"
        
        query = f"""
        SELECT DISTINCT country_code
        FROM `{master_project_id}.ds_master_transformed_data.bestseller_monthly`
        WHERE country_code IS NOT NULL
        ORDER BY country_code ASC
        """
        
        # Execute the query
        query_job = bigquery_client.query(query)
        results = query_job.result()
        
        # Convert to list
        countries = [row.country_code for row in results]
        
        return jsonify({"countries": countries})
    except Exception as e:
        print(f"Error fetching countries: {str(e)}")
        return jsonify({"error": f"Failed to fetch countries: {str(e)}"}), 500

@app.route("/api/dates", methods=["GET"])
@token_required
def get_distinct_dates(current_user, cloud_project_id = None):
    try:
        # Get project_id parameter
        master_project_id = "s360-demand-sensing"

        query = f"""
        SELECT DISTINCT date_month
        FROM `{master_project_id}.ds_master_transformed_data.bestseller_monthly`
        WHERE date_month IS NOT NULL
        ORDER BY date_month DESC
        """
        
        # Execute the query
        query_job = bigquery_client.query(query)
        results = query_job.result()
        
        # Convert to list of date strings in ISO format
        dates = [row.date_month.isoformat() for row in results]
        
        
        return jsonify({"dates": dates})
    except Exception as e:
        print(f"Error fetching dates: {str(e)}")
        return jsonify({"error": f"Failed to fetch dates: {str(e)}"}), 500


@app.route("/api/products/<entity_id>/history", methods=["GET"])
@token_required
@project_access_required
def get_product_history(current_user, entity_id, cloud_project_id=None):
    try:
        # Get query parameters for filtering
        country_code = request.args.get('country_code', None)
        
        # Construct query to get historical rank data for the product
        query = f"""
        SELECT 
            entity_id,
            title,
            date_month,
            rank,
            brand,
            country_code,
            min_price,
            max_price,
            category as category_name
        FROM `s360-demand-sensing.ds_master_transformed_data.bestseller_monthly`
        WHERE entity_id = '{entity_id}'
        """

        # Add country filter if provided
        if country_code:
            query += f" AND country_code = '{country_code}'"
            
        # Order by date
        query += " ORDER BY date_month ASC"

        # Execute the query
        query_job = bigquery_client.query(query)
        results = query_job.result()

        # Convert to list of dictionaries
        history = []
        product_title = ""
        product_brand = ""
        category_name = ""
        
        for row in results:
            if not product_title and row.title:
                product_title = row.title
            if not product_brand and row.brand:
                product_brand = row.brand
            if not category_name and row.category_name:
                category_name = row.category_name
                
            history_point = {
                "entity_id": row.entity_id,
                "date_month": row.date_month.isoformat() if row.date_month else None,
                "avg_rank": row.rank,
                #"product_inventory_status": row.product_inventory_status,
                "country_code": row.country_code,
                "min_price_micros": row.min_price,
                "max_price_micros": row.max_price
            }
            history.append(history_point)

        # Fetch GTINs for this product
        gtin_query = f"""
        SELECT gtin
        FROM `s360-demand-sensing.ds_master_transformed_data.entity_gtins` 
        WHERE entity_id = '{entity_id}'
        """

        gtin_query_job = bigquery_client.query(gtin_query)
        gtin_results = gtin_query_job.result()
        
        # Collect GTINs
        gtins = []
        for row in gtin_results:
            if row.gtin:  # Only add non-None GTINs
                gtins.append(row.gtin)

        return jsonify({
            "entity_id": entity_id,
            "title": product_title,
            "brand": product_brand,
            "category_name": category_name,
            "gtins": gtins,
            "history": history
        })
    
    except Exception as e:
        print(f"Error fetching product history: {str(e)}")
        return jsonify({"error": f"Failed to fetch product history: {str(e)}"}), 500


@app.route("/api/user/preferences", methods=["GET"])
@token_required
def get_user_preferences(current_user):
    """Get user preferences from Firestore"""
    try:
        # Get user document from Firestore
        user_ref = firestore_client.collection('users').document(current_user)
        user_doc = user_ref.get()
        
        if not user_doc.exists:
            # If user doesn't exist yet, return empty preferences
            return jsonify({
                "preferences": {}
            })
        
        # Return preferences if they exist
        user_data = user_doc.to_dict()
        preferences = user_data.get('preferences', {})
        
        return jsonify({
            "preferences": preferences
        })
    except Exception as e:
        print(f"Error getting user preferences: {e}")
        return jsonify({"error": "Error getting user preferences"}), 500

@app.route("/api/user/preferences", methods=["POST"])
@token_required
def save_user_preferences(current_user):
    """Save user preferences to Firestore"""
    try:
        # Get the preferences from the request
        data = request.json
        preferences = data.get('preferences', {})
        
        # Get user document reference
        user_ref = firestore_client.collection('users').document(current_user)
        user_doc = user_ref.get()
        
        if not user_doc.exists:
            # Create new user document if it doesn't exist
            user_ref.set({
                "email": current_user,
                "created_at": firestore.SERVER_TIMESTAMP,
                "preferences": preferences
            })
        else:
            # Update existing user preferences
            current_data = user_doc.to_dict()
            current_preferences = current_data.get('preferences', {})
            
            # Merge the new preferences with existing ones
            merged_preferences = {**current_preferences, **preferences}
            
            # Update the document
            user_ref.update({
                "preferences": merged_preferences,
                "updated_at": firestore.SERVER_TIMESTAMP
            })
        
        return jsonify({
            "success": True,
            "message": "Preferences saved successfully"
        })
    except Exception as e:
        print(f"Error saving user preferences: {e}")
        return jsonify({"error": "Error saving user preferences"}), 500

@app.route("/api/verify-permissions", methods=["POST"])
@token_required_admin
def verify_permissions(current_user):
    try:
        # Get data from request
        data = request.get_json()
        if not data or 'project_id' not in data:
            return jsonify({"error": "Missing project_id in request"}), 400
            
        project_id = data['project_id']
        
        # Get service account from environment variable
        service_account_info = json.loads(os.environ.get("BIGQUERY_SERVICE_ACCOUNT"))
        service_account_email = service_account_info.get("client_email")
        
        if not service_account_email:
            return jsonify({"error": "Service account email not found"}), 500
            
        # Initialize results
        permissions_result = {
            "bigqueryAdmin": False,
            "dataTransferEditor": False,
            "dataTransferServiceAgent": False
        }
        
        # Error messages for better debugging
        error_details = {}
        
        # Create a credentials object for checking
        bq_credentials = service_account.Credentials.from_service_account_info(
            service_account_info
        )
        
        # Test for BigQuery Admin
        try:
            # Create a BigQuery client with the service account credentials
            bq_client = bigquery.Client(credentials=bq_credentials, project=project_id)
            
            # Try to get dataset list to verify admin access
            datasets = list(bq_client.list_datasets(max_results=5))
            
            if datasets:
                # Has visible datasets - likely has admin access
                permissions_result["bigqueryAdmin"] = True
                print(f"BigQuery Admin check succeeded - {len(datasets)} datasets found")
            else:
                # No datasets visible - try to create a temporary dataset to test write permissions
                print("No datasets found. Attempting to create a test dataset...")
                try:
                    # Create a unique dataset ID with timestamp
                    test_dataset_id = f"temp_verify_{uuid.uuid4().hex[:8]}".lower()
                    full_dataset_id = f"{project_id}.{test_dataset_id}"
                    
                    # Define the dataset
                    dataset = bigquery.Dataset(full_dataset_id)
                    dataset.location = "US"  # Specify the location
                    dataset.description = "Temporary dataset for permission verification"
                    
                    # Create the dataset
                    created_dataset = bq_client.create_dataset(dataset, timeout=30)
                    print(f"Created temporary dataset: {created_dataset.dataset_id}")
                    
                    # Clean up - delete the temporary dataset
                    bq_client.delete_dataset(
                        dataset=full_dataset_id,
                        delete_contents=True,
                        not_found_ok=True
                    )
                    print(f"Deleted temporary dataset: {test_dataset_id}")
                    
                    # If we got here, the account has dataset create/delete permissions
                    permissions_result["bigqueryAdmin"] = True
                    print("BigQuery Admin check succeeded - confirmed dataset creation works")
                    
                except Exception as create_err:
                    print(f"Failed to create test dataset: {str(create_err)}")
                    permissions_result["bigqueryAdmin"] = False
                    error_details["bigqueryAdmin"] = str(create_err)
                    print("BigQuery Admin check failed - cannot create datasets")
                    
        except Exception as e:
            print(f"BigQuery Admin check failed: {str(e)}")
            permissions_result["bigqueryAdmin"] = False
            error_details["bigqueryAdmin"] = str(e)


        return jsonify({
            "success": all(permissions_result.values()),
            "permissions": permissions_result,
            "error_details": error_details if any(not v for v in permissions_result.values()) else {}
        })
    except Exception as e:
        print(f"Error verifying permissions: {str(e)}")
        return jsonify({
            "error": f"Failed to verify permissions: {str(e)}",
            "success": False,
            "permissions": {
                "bigqueryAdmin": False,
                "dataTransferEditor": False,
                "dataTransferServiceAgent": False
            }
        }), 500 

@app.route("/api/client-projects", methods=["POST"])
@token_required_admin
def create_client_project(current_user):
    try:
        # Get data from request
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        required_fields = ["name", "cloudProjectId"]
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing required field: {field}"}), 400
        
        # Check if current user is an admin
        user_ref = firestore_client.collection('users').document(current_user)
        user_doc = user_ref.get()
        
        if not user_doc.exists:
            return jsonify({"error": "User not found"}), 404
            
        # Check if the user is an admin
        user_data = user_doc.to_dict()
        is_admin = user_data.get('admin', False)
        
        if not is_admin:
            return jsonify({"error": "Only admins can create projects"}), 403
        
        # Create new project document
        new_project = {
            "name": data["name"],
            "cloudProjectId": data["cloudProjectId"],
            "accessDomains": ["@s360digital.com"],  # Always include s360digital.com
            "accessEmails": [],
            "status": "setting up",
            "createdBy": current_user,
            "createdAt": firestore.SERVER_TIMESTAMP,
            "updatedAt": firestore.SERVER_TIMESTAMP
        }
        
        # Add additional domains and emails if provided
        if "accessDomains" in data and isinstance(data["accessDomains"], list):
            # Don't duplicate @s360digital.com if it's in the input
            additional_domains = [domain for domain in data["accessDomains"] if domain != "@s360digital.com"]
            new_project["accessDomains"].extend(additional_domains)
            
        if "accessEmails" in data and isinstance(data["accessEmails"], list):
            new_project["accessEmails"] = data["accessEmails"]
        
        # Add merchant centers if provided
        if "merchantCenters" in data and isinstance(data["merchantCenters"], list):
            new_project["merchantCenters"] = data["merchantCenters"]
        
        # Add to Firestore
        project_ref = firestore_client.collection('client_projects').document()
        project_ref.set(new_project)
        
        # Get the project with server timestamp
        project_doc = project_ref.get()
        project_data = project_doc.to_dict()
        
        # Format response
        response = {
            "id": project_ref.id,
            "name": project_data.get("name"),
            "cloudProjectId": project_data.get("cloudProjectId"),
            "status": project_data.get("status"),
            "createdBy": project_data.get("createdBy"),
            "createdAt": project_data.get("createdAt"),
            "accessDomains": project_data.get("accessDomains", []),
            "accessEmails": project_data.get("accessEmails", []),
            "merchantCenters": project_data.get("merchantCenters", [])
        }
        
        return jsonify({
            "message": "Project created successfully",
            "project": response
        })
        
    except Exception as e:
        print(f"Error creating client project: {str(e)}")
        return jsonify({"error": f"Failed to create client project: {str(e)}"}), 500

@app.route("/api/client-projects", methods=["GET"])
@token_required
def get_client_projects(current_user):
    try:
        # Check if current user is an admin
        user_ref = firestore_client.collection('users').document(current_user)
        user_doc = user_ref.get()
        
        if not user_doc.exists:
            return jsonify({"error": "User not found"}), 404
            
        # Check if the user is an admin
        user_data = user_doc.to_dict()
        is_admin = user_data.get('admin', False)
        
        if is_admin:
            # Admins can see all projects
            projects_ref = firestore_client.collection('client_projects')
            projects = projects_ref.stream()
        else:
            # Regular users can only see projects they have access to
            # First, get projects where user's email domain matches accessDomains
            user_domain = "@" + current_user.split('@')[1]
            domain_projects_ref = firestore_client.collection('client_projects').where('accessDomains', 'array_contains', user_domain)
            domain_projects = list(domain_projects_ref.stream())
            
            # Second, get projects where user's email is explicitly listed
            email_projects_ref = firestore_client.collection('client_projects').where('accessEmails', 'array_contains', current_user)
            email_projects = list(email_projects_ref.stream())
            
            # Combine the two sets of projects, avoiding duplicates
            project_ids = set()
            projects = []
            
            for project in domain_projects:
                project_ids.add(project.id)
                projects.append(project)
                
            for project in email_projects:
                if project.id not in project_ids:
                    projects.append(project)
        
        # Format results
        result = []
        for project_doc in projects:
            project_data = project_doc.to_dict()
            
            # Process accessDomains and accessEmails with defaults
            accessDomains = project_data.get("accessDomains", [])
            if not isinstance(accessDomains, list):
                accessDomains = []
            if "@s360digital.com" not in accessDomains:
                accessDomains.append("@s360digital.com")
                
            accessEmails = project_data.get("accessEmails", [])
            if not isinstance(accessEmails, list):
                accessEmails = []
                
            result.append({
                "id": project_doc.id,
                "name": project_data.get("name"),
                "cloudProjectId": project_data.get("cloudProjectId"),
                "status": project_data.get("status"),
                "createdBy": project_data.get("createdBy"),
                "createdAt": project_data.get("createdAt"),
                "updatedAt": project_data.get("updatedAt"),
                "accessDomains": accessDomains,
                "accessEmails": accessEmails,
                "merchantCenters": project_data.get("merchantCenters", [])
            })
        
        return jsonify({"projects": result})
        
    except Exception as e:
        print(f"Error fetching client projects: {str(e)}")
        return jsonify({"error": f"Failed to fetch client projects: {str(e)}"}), 500

@app.route("/api/client-projects/<project_id>", methods=["DELETE"])
@token_required_admin
def delete_client_project(current_user, project_id):
    try:
        # Check if current user is an admin
        user_ref = firestore_client.collection('users').document(current_user)
        user_doc = user_ref.get()
        
        if not user_doc.exists:
            return jsonify({"error": "User not found"}), 404
            
        # Check if the user is an admin
        user_data = user_doc.to_dict()
        is_admin = user_data.get('admin', False)
        
        if not is_admin:
            return jsonify({"error": "Only admins can delete projects"}), 403
        
        # Get the project document
        project_ref = firestore_client.collection('client_projects').document(project_id)
        project_doc = project_ref.get()
        
        if not project_doc.exists:
            return jsonify({"error": "Project not found"}), 404
        
        # Delete the project document
        project_ref.delete()
        
        return jsonify({"message": "Project deleted successfully"})
        
    except Exception as e:
        print(f"Error deleting client project: {str(e)}")
        return jsonify({"error": f"Failed to delete client project: {str(e)}"}), 500

@app.route("/api/client-projects/<project_id>", methods=["PUT"])
@token_required_admin
def update_client_project(current_user, project_id):
    try:
        # Check if current user is an admin
        user_ref = firestore_client.collection('users').document(current_user)
        user_doc = user_ref.get()
        
        if not user_doc.exists:
            return jsonify({"error": "User not found"}), 404
            
        # Check if the user is an admin
        user_data = user_doc.to_dict()
        is_admin = user_data.get('admin', False)
        
        if not is_admin:
            return jsonify({"error": "Only admins can update projects"}), 403
        
        # Get data from request
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        # Get the project document
        project_ref = firestore_client.collection('client_projects').document(project_id)
        project_doc = project_ref.get()
        
        if not project_doc.exists:
            return jsonify({"error": "Project not found"}), 404
        
        # Fields that are allowed to be updated
        allowed_fields = ["status", "accessDomains", "accessEmails", "merchantCenters"]
        
        # Create update dictionary
        update_data = {
            "updatedAt": firestore.SERVER_TIMESTAMP,
            "updatedBy": current_user
        }
        
        # Add fields from request data
        for field in allowed_fields:
            if field in data:
                # For accessDomains, always include @s360digital.com
                if field == "accessDomains" and isinstance(data[field], list):
                    # Ensure @s360digital.com is always in the list
                    domains = data[field]
                    if "@s360digital.com" not in domains:
                        domains.append("@s360digital.com")
                    update_data[field] = domains
                else:
                    update_data[field] = data[field]
        
        # Update the project document
        project_ref.update(update_data)
        
        # Get the updated document
        updated_doc = project_ref.get()
        updated_data = updated_doc.to_dict()
        
        # Format response
        response = {
            "id": project_id,
            "name": updated_data.get("name"),
            "cloudProjectId": updated_data.get("cloudProjectId"),
            "status": updated_data.get("status"),
            "createdBy": updated_data.get("createdBy"),
            "createdAt": updated_data.get("createdAt"),
            "updatedAt": updated_data.get("updatedAt"),
            "updatedBy": updated_data.get("updatedBy"),
            "accessDomains": updated_data.get("accessDomains", []),
            "accessEmails": updated_data.get("accessEmails", []),
            "merchantCenters": updated_data.get("merchantCenters", [])
        }
        
        return jsonify({
            "message": "Project updated successfully",
            "project": response
        })
    
    except Exception as e:
        print(f"Error updating client project: {str(e)}")
        return jsonify({"error": f"Failed to update client project: {str(e)}"}), 500

@app.route("/api/client-projects/<project_id>", methods=["GET"])
@token_required_admin
def get_client_project(current_user, project_id):
    try:
        # Check if current user is an admin
        user_ref = firestore_client.collection('users').document(current_user)
        user_doc = user_ref.get()
        
        if not user_doc.exists:
            return jsonify({"error": "User not found"}), 404
            
        # Check if the user is an admin
        user_data = user_doc.to_dict()
        is_admin = user_data.get('admin', False)
        
        # Get the project document
        project_ref = firestore_client.collection('client_projects').document(project_id)
        project_doc = project_ref.get()
        
        if not project_doc.exists:
            return jsonify({"error": "Project not found"}), 404
            
        project_data = project_doc.to_dict()
        
        # If not admin, check if user has access to this project
        if not is_admin:
            user_domain = "@" + current_user.split('@')[1]
            user_has_access = False
            
            # Check domain access
            if "accessDomains" in project_data and isinstance(project_data["accessDomains"], list):
                if user_domain in project_data["accessDomains"]:
                    user_has_access = True
                    
            # Check individual email access
            if not user_has_access and "accessEmails" in project_data and isinstance(project_data["accessEmails"], list):
                if current_user in project_data["accessEmails"]:
                    user_has_access = True
                    
            # Check for s360digital.com domain (always has access)
            if not user_has_access and user_domain == "@s360digital.com":
                user_has_access = True
                
            if not user_has_access:
                return jsonify({"error": "Access denied"}), 403
        
        # Process accessDomains and accessEmails with defaults
        accessDomains = project_data.get("accessDomains", [])
        if not isinstance(accessDomains, list):
            accessDomains = []
        if "@s360digital.com" not in accessDomains:
            accessDomains.append("@s360digital.com")
            
        accessEmails = project_data.get("accessEmails", [])
        if not isinstance(accessEmails, list):
            accessEmails = []
        
        # Format response
        response = {
            "id": project_id,
            "name": project_data.get("name"),
            "cloudProjectId": project_data.get("cloudProjectId"),
            "status": project_data.get("status", "active"),
            "createdBy": project_data.get("createdBy"),
            "createdAt": project_data.get("createdAt"),
            "updatedAt": project_data.get("updatedAt"),
            "updatedBy": project_data.get("updatedBy"),
            "accessDomains": accessDomains,
            "accessEmails": accessEmails,
            "merchantCenters": project_data.get("merchantCenters", [])
        }
        
        return jsonify({"project": response})
        
    except Exception as e:
        print(f"Error fetching client project: {str(e)}")
        return jsonify({"error": f"Failed to fetch client project: {str(e)}"}), 500



@app.route("/api/client-projects/create-data-transfer", methods=["POST"])
@token_required_admin
def create_merchant_transfer_with_sa(current_user):
    try:
        # Parse request data
        request_data = request.json
        cloud_project_id = request_data.get("cloud_project_id")
        merchant_center_id = request_data.get("merchant_center_id")
        client_name = request_data.get("client_name", "").strip()
        market_code = request_data.get("market_code", "").strip()
        dataset_id = "ds_raw_data"

        # Validate inputs
        if not all([cloud_project_id, merchant_center_id]):
            return jsonify({"success": False, "error": "Missing required parameters"}), 400


        # First, create the dataset if it doesn't exist
        # FIX: Use service account credentials here, just like other routes
        credentials_info = json.loads(os.environ.get("BIGQUERY_SERVICE_ACCOUNT"))
        credentials = service_account.Credentials.from_service_account_info(credentials_info)
        bq_client = bigquery.Client(project=cloud_project_id, credentials=credentials)
        
        # Check if dataset exists
        try:
            bq_client.get_dataset(dataset_id)
            logging.info(f"Dataset {dataset_id} already exists in project {cloud_project_id}")
        except Exception:
            logging.info(f"Creating dataset {dataset_id} in project {cloud_project_id}")
            # Dataset doesn't exist, create it
            dataset = bigquery.Dataset(f"{cloud_project_id}.{dataset_id}")
            dataset.location = "EU"
            dataset.description = f"Raw data for Merchant Center {merchant_center_id}"
            
            # Create dataset with custom retry
            retry_count = 0
            max_retries = 3
            dataset_created = False
            
            while retry_count < max_retries and not dataset_created:
                try:
                    bq_client.create_dataset(dataset)
                    dataset_created = True
                    logging.info(f"Created dataset {dataset_id} in project {cloud_project_id}")
                except Exception as dataset_error:
                    retry_count += 1
                    if retry_count >= max_retries:
                        logging.error(f"Failed to create dataset after {max_retries} attempts: {str(dataset_error)}")
                        raise Exception(f"Failed to create dataset: {str(dataset_error)}")
                    logging.warning(f"Dataset creation attempt {retry_count} failed, retrying...")
                    time.sleep(2)  # Wait before retrying
        
        # Initialize the BigQuery Data Transfer client with impersonation
        credentials = service_account.Credentials.from_service_account_info(
            json.loads(os.environ.get("BIGQUERY_SERVICE_ACCOUNT")),
            scopes=['https://www.googleapis.com/auth/cloud-platform'],
            subject="s360-demand-sensing-connector@s360-demand-sensing.iam.gserviceaccount.com"  # Impersonate the new service account
        )
        
        client = bigquery_datatransfer_v1.DataTransferServiceClient(credentials=credentials)
        
        # Set project and location
        parent = f"projects/{cloud_project_id}/locations/EU"
        
        # Create transfer name with new naming convention
        formatted_client_name = client_name.lower().replace(" ", "_") if client_name else "unknown"
        formatted_market = market_code.upper() if market_code else "XX"
        transfer_name = f"ds_{formatted_client_name}_merchant_center_{formatted_market}_{merchant_center_id}"
        
        try:
            # List existing transfers
            list_request = bigquery_datatransfer_v1.ListTransferConfigsRequest(
                parent=parent,
                data_source_ids=["merchant_center"]
            )
            transfers = client.list_transfer_configs(request=list_request)
            
            # Check if any transfer has the same name
            for transfer in transfers:
                if transfer.display_name == transfer_name:
                    # Found an existing transfer with the same name
                    logging.info(f"Found existing transfer {transfer.name} for merchant center {merchant_center_id}")
                    
                    # Check the status of the latest run
                    existing_transfer_name = transfer.name
                    latest_run_request = bigquery_datatransfer_v1.ListTransferRunsRequest(
                        parent=existing_transfer_name,
                        states=[
                            bigquery_datatransfer_v1.TransferState.PENDING,
                            bigquery_datatransfer_v1.TransferState.RUNNING,
                            bigquery_datatransfer_v1.TransferState.SUCCEEDED,
                            bigquery_datatransfer_v1.TransferState.FAILED,
                        ]
                    )
                    
                    latest_runs = client.list_transfer_runs(request=latest_run_request)
                    latest_runs_list = list(latest_runs)
                    
                    if latest_runs_list:
                        latest_run = latest_runs_list[0]  # Most recent run
                        latest_run_state = latest_run.state
                        
                        if latest_run_state == bigquery_datatransfer_v1.TransferState.SUCCEEDED:
                            return jsonify({
                                "success": True,
                                "transfer_exists": True,
                                "transfer_name": existing_transfer_name,
                                "message": f"A data transfer for Merchant Center {merchant_center_id} already exists and is working properly",
                                "dataset": dataset_id,
                                "run_status": "SUCCEEDED",
                                "last_run_time": latest_run.run_time.isoformat() if hasattr(latest_run, 'run_time') else None
                            })
                        elif latest_run_state == bigquery_datatransfer_v1.TransferState.FAILED:
                            return jsonify({
                                "success": True,
                                "transfer_exists": True,
                                "transfer_name": existing_transfer_name,
                                "message": f"A data transfer for Merchant Center {merchant_center_id} already exists but the latest run failed",
                                "dataset": dataset_id,
                                "run_status": "FAILED",
                                "error_details": str(latest_run.error_status) if hasattr(latest_run, 'error_status') else "Unknown error"
                            })
                        elif latest_run_state == bigquery_datatransfer_v1.TransferState.RUNNING:
                            return jsonify({
                                "success": True,
                                "transfer_exists": True,
                                "transfer_name": existing_transfer_name,
                                "message": f"A data transfer for Merchant Center {merchant_center_id} already exists and is currently running",
                                "dataset": dataset_id,
                                "run_status": "RUNNING"
                            })
                        else:  # PENDING or other states
                            return jsonify({
                                "success": True,
                                "transfer_exists": True,
                                "transfer_name": existing_transfer_name,
                                "message": f"A data transfer for Merchant Center {merchant_center_id} already exists and is pending execution",
                                "dataset": dataset_id,
                                "run_status": "PENDING"
                            })
                    else:
                        # No runs found for this transfer
                        return jsonify({
                            "success": True,
                            "transfer_exists": True,
                            "transfer_name": existing_transfer_name,
                            "message": f"A data transfer for Merchant Center {merchant_center_id} already exists but has no run history yet",
                            "dataset": dataset_id,
                            "run_status": "NO_RUNS"
                        })
                    
        except Exception as list_error:
            logging.warning(f"Error checking existing transfers: {str(list_error)}")
            # Continue with creation even if check fails
        
        # Configure the transfer
        transfer_config = bigquery_datatransfer_v1.TransferConfig(
            destination_dataset_id=dataset_id,
            display_name=transfer_name,
            data_source_id="merchant_center",
            params={
                "merchant_id": merchant_center_id,
                "export_products": "true",
                "export_offer_targeting": "true",
                "export_regional_inventories": "true",
                "export_performance": "true",
                "export_best_sellers_v2": "true",
                "export_price_insights": "true",
                "export_local_inventories": "true",
                "export_price_competitiveness": "false",
            },
            schedule="every day 02:00",
        )
        
        # Create the transfer configuration with exception handling for specific errors
        try:
            # First attempt to create the transfer
            response = client.create_transfer_config(parent=parent, transfer_config=transfer_config)
        except Exception as transfer_error:
            error_message = str(transfer_error)
            logging.warning(f"Initial transfer creation failed: {error_message}")
            
            # Check for the specific error about service account token creator permission
            # Improved pattern matching for various error formats
            if (("serviceAccount" in error_message and "serviceAccountTokenCreator" in error_message) or
                ("serviceAccounts.getAccessToken permission" in error_message) or
                ("iam.serviceAccounts.getAccessToken permission" in error_message) or
                ("DTS service agent needs iam.serviceAccounts.getAccessToken permission" in error_message)):
                
                # Extract the service agent email from the error message using multiple patterns
                service_agent_email = None
                
                # Try to match the pattern: service-PROJECT_NUMBER@gcp-sa-bigquerydatatransfer.iam.gserviceaccount.com
                service_agent_match = re.search(r'(service-\d+@gcp-sa-bigquerydatatransfer\.iam\.gserviceaccount\.com)', error_message)
                
                if service_agent_match:
                    service_agent_email = service_agent_match.group(1)
                else:
                    # Try another pattern often seen in the error message
                    service_agent_match = re.search(r'serviceAccount:([^\'"\s]+)', error_message)
                    if service_agent_match:
                        service_agent_email = service_agent_match.group(1)
                    else:
                        # Try to extract from the suggested command line
                        cmd_match = re.search(r'--member=\'serviceAccount:([^\']+)\'', error_message)
                        if cmd_match:
                            service_agent_email = cmd_match.group(1)
                
                if service_agent_email:
                    logging.info(f"Extracted service agent email: {service_agent_email}")
                    
                    # Add IAM binding to allow the service agent to impersonate our service account
                    try:
                        # Create IAM client
                        iam_credentials = service_account.Credentials.from_service_account_info(
                            json.loads(os.environ.get("BIGQUERY_SERVICE_ACCOUNT")),
                            scopes=['https://www.googleapis.com/auth/cloud-platform']
                        )
                        
                        # Create Resource Manager API client to get the project
                        resource_manager = build('cloudresourcemanager', 'v1', credentials=iam_credentials)
                        
                        # Create IAM service
                        iam_service = build('iam', 'v1', credentials=iam_credentials)
                        
                        # The resource name for our service account
                        resource_name = f"projects/s360-demand-sensing/serviceAccounts/s360-demand-sensing-connector@s360-demand-sensing.iam.gserviceaccount.com"
                        
                        # Get the current policy
                        try:
                            policy = iam_service.projects().serviceAccounts().getIamPolicy(resource=resource_name).execute()
                        except Exception as get_policy_error:
                            logging.error(f"Failed to get IAM policy: {str(get_policy_error)}")
                            raise
                        
                        # Initialize bindings if not present
                        if 'bindings' not in policy:
                            policy['bindings'] = []
                        
                        # Check if binding already exists
                        token_creator_binding = None
                        for binding in policy['bindings']:
                            if binding.get('role') == 'roles/iam.serviceAccountTokenCreator':
                                token_creator_binding = binding
                                break
                        
                        # Create the binding if it doesn't exist
                        if not token_creator_binding:
                            token_creator_binding = {
                                'role': 'roles/iam.serviceAccountTokenCreator',
                                'members': []
                            }
                            policy['bindings'].append(token_creator_binding)
                        
                        # Add the service agent as a member if not already present
                        member = f"serviceAccount:{service_agent_email}"
                        if member not in token_creator_binding['members']:
                            token_creator_binding['members'].append(member)
                            
                            # Update the policy
                            updated_policy = iam_service.projects().serviceAccounts().setIamPolicy(
                                resource=resource_name,
                                body={"policy": policy}
                            ).execute()
                            
                            logging.info(f"Added IAM binding for {service_agent_email}")
                            
                            # Wait for the policy to propagate - Google IAM changes can take time
                            # Implement retry mechanism with up to 10 attempts
                            max_retries = 10
                            retry_count = 0
                            transfer_created = False
                            
                            while retry_count < max_retries and not transfer_created:
                                time.sleep(20)  # Wait 20 seconds between each attempt
                                retry_count += 1
                                
                                try:
                                    response = client.create_transfer_config(parent=parent, transfer_config=transfer_config)
                                    logging.info(f"Transfer creation succeeded after adding IAM binding (attempt {retry_count})")
                                    transfer_created = True
                                except Exception as retry_error:
                                    if retry_count >= max_retries:
                                        logging.error(f"Transfer creation failed after {max_retries} attempts: {str(retry_error)}")
                                        raise retry_error
                                    logging.warning(f"Transfer creation attempt {retry_count} failed: {str(retry_error)}. Retrying in 20 seconds...")
                        else:
                            logging.info(f"IAM binding already exists for {service_agent_email}")
                            
                            # Retry creating the transfer since the binding exists with the same retry mechanism
                            max_retries = 10
                            retry_count = 0
                            transfer_created = False
                            
                            while retry_count < max_retries and not transfer_created:
                                if retry_count > 0:  # Don't sleep on first attempt
                                    time.sleep(20)  # Wait 20 seconds between attempts
                                retry_count += 1
                                
                                try:
                                    response = client.create_transfer_config(parent=parent, transfer_config=transfer_config)
                                    logging.info(f"Transfer creation succeeded since IAM binding exists (attempt {retry_count})")
                                    transfer_created = True
                                except Exception as retry_error:
                                    if retry_count >= max_retries:
                                        logging.error(f"Transfer creation failed after {max_retries} attempts: {str(retry_error)}")
                                        raise retry_error
                                    logging.warning(f"Transfer creation attempt {retry_count} failed: {str(retry_error)}. Retrying in 20 seconds...")
                            
                    except Exception as iam_error:
                        logging.error(f"Failed to add IAM binding: {str(iam_error)}")
                        # Re-raise the original error if we couldn't fix it
                        raise transfer_error
                else:
                    # Couldn't extract the service agent email, log the error message for debugging
                    logging.error(f"Could not extract service agent email from error message: {error_message}")
                    raise transfer_error
            else:
                # Not the specific error we're looking for, re-raise
                raise transfer_error
        
        # Log transfer creation
        logging.info(f"Created data transfer for merchant center {merchant_center_id} in project {cloud_project_id}")
        
        # Wait for the first run to be scheduled and check its status
        max_wait_time = 60  # Maximum wait time in seconds
        wait_interval = 5   # Check interval in seconds
        total_wait_time = 0
        transfer_config_name = response.name
        
        # Wait until a transfer run is created or max_wait_time is reached
        while total_wait_time < max_wait_time:
            # List transfer runs for this config
            parent = transfer_config_name
            runs_list_request = bigquery_datatransfer_v1.ListTransferRunsRequest(
                parent=parent,
                states=[
                    bigquery_datatransfer_v1.TransferState.PENDING,
                    bigquery_datatransfer_v1.TransferState.RUNNING,
                    bigquery_datatransfer_v1.TransferState.SUCCEEDED,
                    bigquery_datatransfer_v1.TransferState.FAILED,
                ]
            )
            
            runs = client.list_transfer_runs(request=runs_list_request)
            runs_list = list(runs)
            
            if runs_list:
                # Found at least one run
                latest_run = runs_list[0]  # Runs are ordered by most recent first
                
                # Check run state
                if latest_run.state == bigquery_datatransfer_v1.TransferState.SUCCEEDED:
                    logging.info(f"Transfer run {latest_run.name} succeeded")
                    return jsonify({
                        "success": True,
                        "transfer_exists": False,
                        "transfer_name": transfer_config_name,
                        "message": "Data transfer created and first run succeeded",
                        "dataset": dataset_id,
                        "run_status": "SUCCEEDED"
                    })
                elif latest_run.state == bigquery_datatransfer_v1.TransferState.FAILED:
                    logging.error(f"Transfer run {latest_run.name} failed: {latest_run.error_status}")
                    return jsonify({
                        "success": False,
                        "transfer_exists": False,
                        "transfer_name": transfer_config_name,
                        "message": "Data transfer created but first run failed",
                        "dataset": dataset_id,
                        "run_status": "FAILED",
                        "error_details": str(latest_run.error_status)
                    }), 500
                elif latest_run.state == bigquery_datatransfer_v1.TransferState.RUNNING:
                    logging.info(f"Transfer run {latest_run.name} is still running")
                    # Since runs can take a while, we'll return 202 Accepted with the running status
                    return jsonify({
                        "success": True,
                        "transfer_exists": False,
                        "transfer_name": transfer_config_name,
                        "message": "Data transfer created and run is in progress",
                        "dataset": dataset_id,
                        "run_status": "RUNNING"
                    }), 202
                else:
                    # Run is in PENDING state
                    logging.info(f"Transfer run {latest_run.name} is pending")
            
            # Wait and check again
            time.sleep(wait_interval)
            total_wait_time += wait_interval
        
        # If we've waited the maximum time without a run completing or failing,
        # return success for the creation but note the pending status
        return jsonify({
            "success": True,
            "transfer_exists": False,
            "transfer_name": transfer_config_name,
            "message": "Data transfer created successfully but no run completed within timeout period",
            "dataset": dataset_id,
            "run_status": "PENDING_OR_NOT_STARTED"
        }), 202
        
    except Exception as e:
        error_message = str(e)
        logging.error(f"Error creating data transfer: {error_message}")
        
        # Special handling for service account token permission errors
        if "serviceAccounts.getAccessToken permission" in error_message or "iam.serviceAccounts.getAccessToken permission" in error_message:
            # Extract the service agent email from the error message for client information
            service_agent_match = re.search(r'(service-\d+@gcp-sa-bigquerydatatransfer\.iam\.gserviceaccount\.com)', error_message)
            
            if service_agent_match:
                service_agent_email = service_agent_match.group(1)
                return jsonify({
                    "success": False, 
                    "error": "Failed to add required permissions automatically. Please try again.",
                    "error_details": error_message,
                    "service_agent_email": service_agent_email,
                    "missing_permission": "token_creator"
                }), 400
        
        # Check for other specific error conditions
        if "dataset" in error_message.lower() and "not found" in error_message.lower():
            return jsonify({
                "success": False, 
                "error": f"Dataset '{dataset_id}' could not be created. Please check permissions.",
                "error_details": error_message
            }), 400
        elif "billing is disabled" in error_message.lower() or "billing not enabled" in error_message.lower():
            # Specific handling for billing disabled error
            return jsonify({
                "success": False, 
                "error": "Billing is disabled for this project. Please enable billing to continue.",
                "error_details": error_message,
                "billing_disabled": True
            }), 400
        elif "permission" in error_message.lower() or "access" in error_message.lower():
            return jsonify({
                "success": False, 
                "error": "Insufficient permissions to create data transfer. Please check service account permissions.",
                "error_details": error_message
            }), 403
        elif "BigQuery Data Transfer service has not been used" in error_message or "disabled" in error_message:
            # Specific handling for API not enabled error
            return jsonify({
                "success": False, 
                "error": f"The BigQuery Data Transfer API is not enabled for this project.",
                "error_details": error_message,
                "api_disabled": True
            }), 400
        else:
            return jsonify({
                "success": False, 
                "error": "Failed to create data transfer", 
                "error_details": error_message
            }), 500

@app.route("/api/verify-merchant-connection", methods=["POST"])
@token_required_admin
def verify_merchant_connection(current_user):
    try:
        # Get data from request
        data = request.get_json()
        if 'merchant_center_id' not in data:
            return jsonify({"error": "Missing cloud_project_id or merchant_center_id in request"}), 400
            
        merchant_center_id = data['merchant_center_id']
        
        # Create service account credentials
        service_account_info = json.loads(os.environ.get("BIGQUERY_SERVICE_ACCOUNT"))
        credentials = service_account.Credentials.from_service_account_info(
            service_account_info,
            scopes=["https://www.googleapis.com/auth/content"]
        )
        
        # Create the Content API client
        content_service = build('content', 'v2.1', credentials=credentials)
        
        try:
            # First try to get product data to extract feed labels (markets)
            markets = []
            default_market_code = None
            
            # Try to fetch products to identify feed labels
            products_request = content_service.products().list(
                merchantId=merchant_center_id,
                maxResults=100
            )
            products_response = products_request.execute()

            # Extract all unique feed labels from the response
            feed_labels = set()
            target_countries = set()
            
            if 'resources' in products_response and len(products_response['resources']) > 0:
                for product in products_response['resources']:
                    # Add feed label if present
                    if 'feedLabel' in product and product['feedLabel']:
                        feed_labels.add(product['feedLabel'])
                    
                    # Add target country as fallback
                    if 'targetCountry' in product:
                        target_countries.add(product['targetCountry'])
            
            # If we found feed labels, use them as primary markets
            for feed_label in feed_labels:
                markets.append({
                    "code": feed_label,
                    "source": "feed_label"
                })
            
            # For countries without specific feed labels, add them as secondary markets
            for country in target_countries:
                # Only add if not already covered by a feed label
                if country not in feed_labels:
                    markets.append({
                        "code": country,
                        "source": "target_country"
                    })
            
            # Try to get a default market from shipping settings if no products were found
            if not markets:
                try:
                    # Get shipping settings (merchant ID is same as account ID in this case)
                    shipping_settings = content_service.shippingsettings().get(
                        merchantId=merchant_center_id,
                        accountId=merchant_center_id
                    ).execute()
                    
                    # Check if services are defined with country information
                    if 'services' in shipping_settings and shipping_settings['services']:
                        for service in shipping_settings['services']:
                            if 'deliveryCountry' in service:
                                default_market_code = service['deliveryCountry']
                                markets.append({
                                    "code": default_market_code,
                                    "source": "shipping_settings"
                                })
                                break
                except Exception as shipping_error:
                    # If shipping settings retrieval fails, continue with what we have
                    print(f"Could not get shipping settings: {str(shipping_error)}")
            
            # If we still don't have any market code, use a default one
            if not markets:
                markets.append({
                    "code": "XX",  # Default placeholder
                    "source": "default"
                })
            
            # If we got here without error, the connection works
            return jsonify({
                "success": True,
                "message": "Successfully connected to Merchant Center",
                "markets": markets,
                "default_market_code": default_market_code or (markets[0]["code"] if markets else None)
            })
            
        except Exception as api_error:
            print(f"Merchant Center API error: {str(api_error)}")
            error_message = str(api_error)
            
            if "permission" in error_message.lower() or "access" in error_message.lower():
                # Permission issue
                return jsonify({
                    "success": False,
                    "error": f"The service account doesn't have access to this Merchant Center. Please add s360-demand-sensing-connector@s360-demand-sensing.iam.gserviceaccount.com to your Merchant Center with standard access."
                }), 403
            elif "not found" in error_message.lower():
                # Merchant Center ID not found
                return jsonify({
                    "success": False,
                    "error": f"Merchant Center ID '{merchant_center_id}' not found. Please check the ID and try again."
                }), 404
            else:
                # Other error
                return jsonify({
                    "success": False,
                    "error": f"Error connecting to Merchant Center: {error_message}"
                }), 500
        
    except Exception as e:
        print(f"Error verifying merchant connection: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Failed to verify merchant connection: {str(e)}"
        }), 500


@app.route("/api/client-projects/<project_id>/transfers", methods=["GET"])
@token_required_admin
def get_project_transfer_status(current_user, project_id):
    try:
        # Get the project document
        project_ref = firestore_client.collection('client_projects').document(project_id)
        project_doc = project_ref.get()
        
        if not project_doc.exists:
            return jsonify({"error": "Project not found"}), 404
            
        project_data = project_doc.to_dict()
        cloud_project_id = project_data.get("cloudProjectId")
        merchant_centers = project_data.get("merchantCenters", [])
        
        if not cloud_project_id:
            return jsonify({"error": "Cloud project ID not found"}), 400
            
        if not merchant_centers:
            return jsonify({"success": True, "transfers": [], "message": "No merchant centers configured for this project"}), 200
            
        # Initialize the BigQuery Data Transfer client with impersonation
        credentials = service_account.Credentials.from_service_account_info(
            json.loads(os.environ.get("BIGQUERY_SERVICE_ACCOUNT")),
            scopes=['https://www.googleapis.com/auth/cloud-platform'],
            subject="s360-demand-sensing-connector@s360-demand-sensing.iam.gserviceaccount.com"
        )
        
        client = bigquery_datatransfer_v1.DataTransferServiceClient(credentials=credentials)
        
        # Set project and location
        parent = f"projects/{cloud_project_id}/locations/EU"
        
        # Collect transfer data for each merchant center
        transfers_data = []
        
        try:
            # List all transfers for the project
            list_request = bigquery_datatransfer_v1.ListTransferConfigsRequest(
                parent=parent,
                data_source_ids=["merchant_center"]
            )
            
            transfers = client.list_transfer_configs(request=list_request)
            transfers_list = list(transfers)
            
            # Format client name for matching with transfer names
            formatted_client_name = project_data.get("name", "").lower().replace(" ", "_")
            
            for merchant_center in merchant_centers:
                merchant_center_id = merchant_center.get("merchantCenterId", "")
                market_code = merchant_center.get("code", "")
                
                if not merchant_center_id:
                    continue
                
                # Find matching transfer
                matching_transfer = None
                
                for transfer in transfers_list:
                    # Check if this transfer belongs to the merchant center
                    if merchant_center_id in transfer.display_name:
                        matching_transfer = transfer
                        break
                
                transfer_info = {
                    "merchant_center_id": merchant_center_id,
                    "market_code": market_code,
                    "exists": False,
                    "transfer_name": "",
                    "display_name": "",
                    "last_run_status": "NOT_FOUND",
                    "last_run_time": None,
                    "next_run_time": None,
                    "error_details": None,
                    "schedule": "",
                    "run_history": []
                }
                
                if matching_transfer:
                    transfer_info["exists"] = True
                    transfer_info["transfer_name"] = matching_transfer.name
                    transfer_info["display_name"] = matching_transfer.display_name
                    
                    if hasattr(matching_transfer, 'schedule'):
                        transfer_info["schedule"] = matching_transfer.schedule
                    
                    # Enum to string mapping for transfer states
                    state_enum_to_string = {
                        bigquery_datatransfer_v1.TransferState.SUCCEEDED: "SUCCEEDED",
                        bigquery_datatransfer_v1.TransferState.FAILED: "FAILED",
                        bigquery_datatransfer_v1.TransferState.RUNNING: "RUNNING",
                        bigquery_datatransfer_v1.TransferState.PENDING: "PENDING",
                        bigquery_datatransfer_v1.TransferState.CANCELLED: "CANCELLED",
                    }
                    
                    # Get multiple runs instead of just the latest one (max 10 runs)
                    latest_runs_request = bigquery_datatransfer_v1.ListTransferRunsRequest(
                        parent=matching_transfer.name,
                        page_size=10
                    )
                    
                    latest_runs = client.list_transfer_runs(request=latest_runs_request)
                    latest_runs_list = list(latest_runs)
                    
                    if latest_runs_list:
                        # Set the overall status from the most recent run
                        latest_run = latest_runs_list[0]  # Most recent run
                        transfer_info["last_run_status"] = state_enum_to_string.get(latest_run.state, "UNKNOWN")
                        
                        if hasattr(latest_run, 'run_time') and latest_run.run_time:
                            transfer_info["last_run_time"] = latest_run.run_time.isoformat()
                            
                        if hasattr(latest_run, 'error_status') and latest_run.error_status:
                            transfer_info["error_details"] = str(latest_run.error_status)
                        
                        # Add run history
                        for run in latest_runs_list:
                            run_info = {
                                "state": state_enum_to_string.get(run.state, "UNKNOWN"),
                                "run_time": run.run_time.isoformat() if hasattr(run, 'run_time') and run.run_time else None,
                                "start_time": run.start_time.isoformat() if hasattr(run, 'start_time') and run.start_time else None,
                                "end_time": run.end_time.isoformat() if hasattr(run, 'end_time') and run.end_time else None,
                                "update_time": run.update_time.isoformat() if hasattr(run, 'update_time') and run.update_time else None,
                                "error_details": str(run.error_status) if hasattr(run, 'error_status') and run.error_status else None
                            }
                            transfer_info["run_history"].append(run_info)
                    
                    # Add next scheduled run time if available
                    if hasattr(matching_transfer, 'next_run_time') and matching_transfer.next_run_time:
                        transfer_info["next_run_time"] = matching_transfer.next_run_time.isoformat()
                
                transfers_data.append(transfer_info)
        
        except Exception as list_error:
            logging.error(f"Error listing transfers: {str(list_error)}")
            return jsonify({
                "success": False,
                "error": "Failed to list transfers",
                "error_details": str(list_error)
            }), 500
        
        return jsonify({
            "success": True,
            "transfers": transfers_data,
            "project_name": project_data.get("name", ""),
            "cloud_project_id": cloud_project_id
        })
        
    except Exception as e:
        logging.error(f"Error getting project transfer status: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Failed to get project transfer status",
            "error_details": str(e)
        }), 500

@app.route("/api/client-projects/check-setup-status", methods=["GET"])
@token_required_admin
def check_setup_status(current_user):
    try:
        # Find all projects with status "setting up"
        setup_projects_ref = firestore_client.collection('client_projects').where('status', '==', 'setting up')
        setup_projects = list(setup_projects_ref.stream())
        
        if not setup_projects:
            return jsonify({
                "success": True,
                "message": "No projects in setup status",
                "updated_projects": []
            })
        
        updated_projects = []
        
        for project_doc in setup_projects:
            project_data = project_doc.to_dict()
            project_id = project_doc.id
            cloud_project_id = project_data.get("cloudProjectId")
            merchant_centers = project_data.get("merchantCenters", [])
            
            # Skip if no merchant centers
            if not merchant_centers or not cloud_project_id:
                continue
            
            # Check if all merchant center transfers were successful
            all_transfers_ok = True
            
            try:
                # Initialize the BigQuery Data Transfer client with impersonation
                credentials = service_account.Credentials.from_service_account_info(
                    json.loads(os.environ.get("BIGQUERY_SERVICE_ACCOUNT")),
                    scopes=['https://www.googleapis.com/auth/cloud-platform'],
                    subject="s360-demand-sensing-connector@s360-demand-sensing.iam.gserviceaccount.com"
                )
                
                client = bigquery_datatransfer_v1.DataTransferServiceClient(credentials=credentials)
                
                # Set project and location
                parent = f"projects/{cloud_project_id}/locations/EU"
                
                # List all transfers for the project
                list_request = bigquery_datatransfer_v1.ListTransferConfigsRequest(
                    parent=parent,
                    data_source_ids=["merchant_center"]
                )
                
                transfers = client.list_transfer_configs(request=list_request)
                transfers_list = list(transfers)
                
                # Check if each merchant center has a successful transfer
                for merchant_center in merchant_centers:
                    merchant_center_id = merchant_center.get("merchantCenterId", "")
                    
                    if not merchant_center_id:
                        continue
                    
                    # Find matching transfer
                    matching_transfer = None
                    for transfer in transfers_list:
                        if merchant_center_id in transfer.display_name:
                            matching_transfer = transfer
                            break
                    
                    # If no matching transfer found, mark as not ready
                    if not matching_transfer:
                        all_transfers_ok = False
                        break
                    
                    # Check the latest run for this transfer
                    latest_run_request = bigquery_datatransfer_v1.ListTransferRunsRequest(
                        parent=matching_transfer.name,
                        states=[
                            bigquery_datatransfer_v1.TransferState.SUCCEEDED,
                            bigquery_datatransfer_v1.TransferState.FAILED,
                            bigquery_datatransfer_v1.TransferState.RUNNING,
                            bigquery_datatransfer_v1.TransferState.PENDING,
                        ],
                        page_size=1
                    )
                    
                    latest_runs = client.list_transfer_runs(request=latest_run_request)
                    latest_runs_list = list(latest_runs)
                    
                    # If no runs or the latest run is not successful, mark as not ready
                    if not latest_runs_list or latest_runs_list[0].state != bigquery_datatransfer_v1.TransferState.SUCCEEDED:
                        all_transfers_ok = False
                        break
                
                # Update the project status if all transfers are OK
                if all_transfers_ok:
                    project_ref = firestore_client.collection('client_projects').document(project_id)
                    project_ref.update({
                        "status": "active",
                        "updatedAt": firestore.SERVER_TIMESTAMP,
                        "updatedBy": "system"
                    })
                    
                    # Add to list of updated projects
                    updated_projects.append({
                        "id": project_id,
                        "name": project_data.get("name"),
                        "previous_status": "setting up",
                        "new_status": "active"
                    })
                    
                    logging.info(f"Project {project_id} ({project_data.get('name')}) status updated from 'setting up' to 'active'")
                
            except Exception as e:
                logging.error(f"Error checking transfers for project {project_id}: {str(e)}")
                # Continue with next project
        
        return jsonify({
            "success": True,
            "message": f"Checked {len(setup_projects)} projects, updated {len(updated_projects)}",
            "updated_projects": updated_projects
        })
        
    except Exception as e:
        logging.error(f"Error checking setup status: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Failed to check setup status",
            "error_details": str(e)
        }), 500

@app.route("/api/client-projects/<project_id>/merchant-centers", methods=["GET"])
@token_required
def get_project_merchant_centers(current_user, project_id):
    try:
        # Get the project document
        project_ref = firestore_client.collection('client_projects').document(project_id)
        project_doc = project_ref.get()
        
        if not project_doc.exists:
            return jsonify({"error": "Project not found"}), 404
            
        project_data = project_doc.to_dict()
        
        # Check if user has access to this project
        user_domain = "@" + current_user.split('@')[1]
        user_has_access = False
        
        # Check domain access
        if "accessDomains" in project_data and isinstance(project_data["accessDomains"], list):
            if user_domain in project_data["accessDomains"]:
                user_has_access = True
        
        # Check individual email access
        if not user_has_access and "accessEmails" in project_data and isinstance(project_data["accessEmails"], list):
            if current_user in project_data["accessEmails"]:
                user_has_access = True
        
        # Access denied if user doesn't have access to the project
        if not user_has_access:
            return jsonify({"error": "You don't have access to this project"}), 403
        
        # Extract merchant centers data
        merchant_centers = project_data.get("merchantCenters", [])

        # Return merchant centers with their codes and IDs
        return jsonify({
            "merchant_centers": merchant_centers,
            "project_name": project_data.get("name", "")
        })
        
    except Exception as e:
        print(f"Error fetching project merchant centers: {str(e)}")
        return jsonify({"error": f"Failed to fetch merchant centers: {str(e)}"}), 500

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

# Favorites API endpoints
@app.route("/api/favorites", methods=["GET"])
@token_required
def get_user_favorites(current_user):
    """Get all favorites for the current user"""
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
            cursor.execute(
                "SELECT * FROM user_favorites WHERE user_email = %s",
                (current_user,)
            )
            favorites = [dict(row) for row in cursor.fetchall()]
            
        return jsonify({
            "success": True,
            "favorites": favorites
        })
    except Exception as e:
        print(f"Error fetching favorites: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Failed to fetch favorites: {str(e)}"
        }), 500
    finally:
        conn.close()

@app.route("/api/favorites", methods=["POST"])
@token_required
def add_favorite(current_user):
    """Add a new favorite for the current user"""
    try:
        data = request.json
        if not data or "entity_id" not in data:
            return jsonify({
                "success": False,
                "error": "Missing required field: entity_id"
            }), 400
            
        entity_id = data["entity_id"]
        country_code = data.get("country_code", None)
        project_id = data.get("project_id", None)
        
        # Validate project_id is provided since it's part of the primary key
        if not project_id:
            return jsonify({
                "success": False,
                "error": "Missing required field: project_id"
            }), 400
        
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO user_favorites (user_email, entity_id, country_code, project_id)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (user_email, entity_id, project_id) DO UPDATE 
                SET country_code = EXCLUDED.country_code
                """,
                (current_user, entity_id, country_code, project_id)
            )
            
        return jsonify({
            "success": True,
            "message": "Favorite added successfully"
        })
    except Exception as e:
        print(f"Error adding favorite: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Failed to add favorite: {str(e)}"
        }), 500
    finally:
        conn.close()

@app.route("/api/favorites/<entity_id>", methods=["DELETE"])
@token_required
def remove_favorite(current_user, entity_id):
    """Remove a favorite for the current user"""
    try:
        # Get project_id parameter from query string
        project_id = request.args.get("project_id", None)
        
        conn = get_db_connection()
        with conn.cursor() as cursor:
            # If project_id is provided, use it in the delete condition
            if project_id:
                cursor.execute(
                    "DELETE FROM user_favorites WHERE user_email = %s AND entity_id = %s AND project_id = %s",
                    (current_user, entity_id, project_id)
                )
            else:
                # Backward compatibility: delete all favorites with this entity_id
                cursor.execute(
                    "DELETE FROM user_favorites WHERE user_email = %s AND entity_id = %s",
                    (current_user, entity_id)
                )
            
        return jsonify({
            "success": True,
            "message": "Favorite removed successfully"
        })
    except Exception as e:
        print(f"Error removing favorite: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Failed to remove favorite: {str(e)}"
        }), 500
    finally:
        conn.close()

# List management API endpoints
@app.route("/api/lists", methods=["GET"])
@token_required
def get_user_lists(current_user):
    """Get all lists the user has access to"""
    try:
        # Get project_id parameter
        project_id = request.args.get('project_id', None)
        if not project_id:
            return jsonify({"error": "Missing project_id parameter"}), 400
            
        # Get lists from Firestore where user is owner or has access
        lists_ref = firestore_client.collection('user_lists')
        owner_lists = list(lists_ref.where('owner', '==', current_user).where('project_id', '==', project_id).stream())
        shared_lists = list(lists_ref.where('shared_with', 'array_contains', current_user).where('project_id', '==', project_id).stream())
        
        # Combine lists
        all_lists = []
        for list_doc in owner_lists + shared_lists:
            list_data = list_doc.to_dict()
            list_data['id'] = list_doc.id
            list_data['is_owner'] = list_data.get('owner') == current_user
            all_lists.append(list_data)
            
        return jsonify({
            "success": True,
            "lists": all_lists
        })
    except Exception as e:
        print(f"Error fetching lists: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Failed to fetch lists: {str(e)}"
        }), 500

@app.route("/api/lists", methods=["POST"])
@token_required
def create_list(current_user):
    """Create a new list"""
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        required_fields = ["name", "project_id", "country_code"]
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing required field: {field}"}), 400
        
        # Create new list document
        new_list = {
            "name": data["name"],
            "description": data.get("description", ""),
            "project_id": data["project_id"],
            "country_code": data["country_code"],
            "owner": current_user,
            "shared_with": [],
            "created_at": firestore.SERVER_TIMESTAMP,
            "updated_at": firestore.SERVER_TIMESTAMP
        }
        
        # Add to Firestore
        list_ref = firestore_client.collection('user_lists').document()
        list_ref.set(new_list)
        
        # Get the list with server timestamp
        list_doc = list_ref.get()
        list_data = list_doc.to_dict()
        list_data['id'] = list_ref.id
        list_data['is_owner'] = True
        
        return jsonify({
            "success": True,
            "message": "List created successfully",
            "list": list_data
        })
    except Exception as e:
        print(f"Error creating list: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Failed to create list: {str(e)}"
        }), 500

@app.route("/api/lists/<list_id>", methods=["PUT"])
@token_required
def update_list(current_user, list_id):
    """Update a list's metadata"""
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        # Get the list document
        list_ref = firestore_client.collection('user_lists').document(list_id)
        list_doc = list_ref.get()
        
        if not list_doc.exists:
            return jsonify({"error": "List not found"}), 404
            
        list_data = list_doc.to_dict()
        
        # Only the owner can update the list
        if list_data.get('owner') != current_user:
            return jsonify({"error": "You don't have permission to update this list"}), 403
            
        # Fields that are allowed to be updated
        allowed_fields = ["name", "description"]
        
        # Create update dictionary
        update_data = {
            "updated_at": firestore.SERVER_TIMESTAMP
        }
        
        # Add fields from request data
        for field in allowed_fields:
            if field in data:
                update_data[field] = data[field]
        
        # Update the list document
        list_ref.update(update_data)
        
        # Get the updated document
        updated_doc = list_ref.get()
        updated_data = updated_doc.to_dict()
        updated_data['id'] = list_id
        updated_data['is_owner'] = updated_data.get('owner') == current_user
        
        return jsonify({
            "success": True,
            "message": "List updated successfully",
            "list": updated_data
        })
    except Exception as e:
        print(f"Error updating list: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Failed to update list: {str(e)}"
        }), 500

@app.route("/api/lists/<list_id>", methods=["DELETE"])
@token_required
def delete_list(current_user, list_id):
    """Delete a list and all its items"""
    try:
        # Get the list document
        list_ref = firestore_client.collection('user_lists').document(list_id)
        list_doc = list_ref.get()
        
        if not list_doc.exists:
            return jsonify({"error": "List not found"}), 404
            
        list_data = list_doc.to_dict()
        
        # Only the owner can delete the list
        if list_data.get('owner') != current_user:
            return jsonify({"error": "You don't have permission to delete this list"}), 403
            
        # Start a transaction to delete both the list metadata and items
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                # Delete all items in the list from PostgreSQL
                cursor.execute(
                    "DELETE FROM user_lists WHERE list_id = %s",
                    (list_id,)
                )
                
                # Delete the list metadata from Firestore
                list_ref.delete()
                
                return jsonify({
                    "success": True,
                    "message": "List deleted successfully"
                })
        finally:
            conn.close()
    except Exception as e:
        print(f"Error deleting list: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Failed to delete list: {str(e)}"
        }), 500

@app.route("/api/lists/<list_id>/items", methods=["GET"])
@token_required
def get_list_items(current_user, list_id):
    """Get all items in a list"""
    try:
        # Get the list document to check access
        list_ref = firestore_client.collection('user_lists').document(list_id)
        list_doc = list_ref.get()
        
        if not list_doc.exists:
            return jsonify({"error": "List not found"}), 404
            
        list_data = list_doc.to_dict()
        
        # Check if user has access to this list
        if list_data.get('owner') != current_user and current_user not in list_data.get('shared_with', []):
            return jsonify({"error": "You don't have access to this list"}), 403
            
        # Get items from PostgreSQL
        conn = get_db_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                cursor.execute(
                    "SELECT * FROM user_lists WHERE list_id = %s",
                    (list_id,)
                )
                items = [dict(row) for row in cursor.fetchall()]
                
                # Get additional product details for each entity_id
                # If we have at least one item, fetch product details
                if items:
                    # Get project ID and merchant center ID
                    project_id = list_data.get('project_id')
                    cloud_project_id = None
                    merchant_center_id = None
                    
                    # Get cloud project ID from client_projects collection
                    project_ref = firestore_client.collection('client_projects').document(project_id)
                    project_doc = project_ref.get()
                    if project_doc.exists:
                        project_data = project_doc.to_dict()
                        cloud_project_id = project_data.get('cloudProjectId')
                        
                        # Get merchant center ID for the country
                        country_code = list_data.get('country_code')
                        for mc in project_data.get('merchantCenters', []):
                            if mc.get('code') == country_code:
                                merchant_center_id = mc.get('merchantCenterId')
                                break
                    
                    # If we have cloud project ID and merchant center ID, fetch product details
                    if cloud_project_id and merchant_center_id:
                        # Extract all entity IDs
                        entity_ids = [item['entity_id'] for item in items]
                        
                        # Create a placeholder string for the IN clause
                        placeholders = ', '.join([f"'{entity_id}'" for entity_id in entity_ids])
                        
                        # Query for detailed product information
                        query = f"""
                        WITH main_bestseller AS (
                          SELECT DISTINCT
                            report_category_id,
                            category,
                            category_l2,
                            category_l3,
                            entity_id,
                            title,
                            country_code,
                            brand,
                            date_month,
                            rank AS avg_rank
                          FROM `s360-demand-sensing.ds_master_transformed_data.bestseller_monthly`
                          WHERE entity_id IN ({placeholders})
                          AND country_code = '{list_data.get('country_code')}'
                          ORDER BY date_month DESC
                        ),
                        client_data AS (
                          SELECT
                            COALESCE(products.feed_label, products.target_country) AS country_code,
                            mapping.entity_id,
                            products.availability
                          FROM
                            (
                              SELECT DISTINCT
                                product_id,
                                feed_label,
                                target_country,
                                availability
                              FROM `{cloud_project_id}.ds_raw_data.Products_{merchant_center_id}`
                              WHERE _PARTITIONTIME = (
                                SELECT MAX(_PARTITIONTIME)
                                FROM `{cloud_project_id}.ds_raw_data.Products_{merchant_center_id}`
                              )
                              AND channel = 'online'
                              AND feed_label IN ("{country_code}")
                            ) AS products
                          LEFT JOIN
                            (
                              SELECT
                                product_id,
                                entity_id
                              FROM `{cloud_project_id}.ds_raw_data.BestSellersEntityProductMapping_{merchant_center_id}`
                              WHERE _PARTITIONTIME = (
                                SELECT MAX(_PARTITIONTIME)
                                FROM `{cloud_project_id}.ds_raw_data.BestSellersEntityProductMapping_{merchant_center_id}`
                              )
                            ) AS mapping
                            ON mapping.product_id = products.product_id
                        )
                        SELECT DISTINCT
                          main_bestseller.report_category_id,
                          main_bestseller.category,
                          main_bestseller.category_l2,
                          main_bestseller.category_l3,
                          main_bestseller.entity_id,
                          main_bestseller.title,
                          main_bestseller.country_code,
                          main_bestseller.brand,
                          main_bestseller.date_month,
                          main_bestseller.avg_rank,
                          CASE 
                            WHEN client_data.availability IS NOT NULL THEN 'IN_STOCK'
                            ELSE 'NOT_IN_INVENTORY'
                          END AS product_inventory_status
                        FROM main_bestseller
                        LEFT JOIN client_data 
                        ON main_bestseller.entity_id = client_data.entity_id
                        AND main_bestseller.country_code = client_data.country_code
                        """
                        
                        # Execute the query
                        query_job = bigquery_client.query(query)
                        results = query_job.result()
                        
                        # Create a dictionary of product details by entity_id
                        product_details = {}
                        for row in results:
                            if row.entity_id not in product_details:
                                product_details[row.entity_id] = {
                                    "report_category_id": row.report_category_id,
                                    "category": row.category,
                                    "category_l2": row.category_l2,
                                    "category_l3": row.category_l3,
                                    "entity_id": row.entity_id,
                                    "title": row.title,
                                    "country_code": row.country_code,
                                    "brand": row.brand,
                                    "date_month": row.date_month.isoformat() if row.date_month else None,
                                    "avg_rank": row.avg_rank,
                                    "product_inventory_status": row.product_inventory_status
                                }
                        
                        # Add product details to items
                        for item in items:
                            entity_id = item['entity_id']
                            if entity_id in product_details:
                                item.update(product_details[entity_id])
                
                return jsonify({
                    "success": True,
                    "items": items,
                    "list_metadata": {
                        "id": list_id,
                        "name": list_data.get('name'),
                        "description": list_data.get('description', ''),
                        "country_code": list_data.get('country_code'),
                        "project_id": list_data.get('project_id'),
                        "owner": list_data.get('owner'),
                        "shared_with": list_data.get('shared_with', []),
                        "is_owner": list_data.get('owner') == current_user
                    }
                })
        finally:
            conn.close()
    except Exception as e:
        print(f"Error fetching list items: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Failed to fetch list items: {str(e)}"
        }), 500

@app.route("/api/lists/<list_id>/items/with-gtins", methods=["GET"])
@token_required
def get_list_items_with_gtins(current_user, list_id):
    """Get all items in a list with their GTINs"""
    try:
        # Get the list document to check access
        list_ref = firestore_client.collection('user_lists').document(list_id)
        list_doc = list_ref.get()
        
        if not list_doc.exists:
            return jsonify({"error": "List not found"}), 404
            
        list_data = list_doc.to_dict()
        
        # Check if user has access to this list
        if list_data.get('owner') != current_user and current_user not in list_data.get('shared_with', []):
            return jsonify({"error": "You don't have access to this list"}), 403
            
        # Get items from PostgreSQL
        conn = get_db_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                cursor.execute(
                    "SELECT * FROM user_lists WHERE list_id = %s",
                    (list_id,)
                )
                items = [dict(row) for row in cursor.fetchall()]
                
                # Get additional product details for each entity_id
                # If we have at least one item, fetch product details
                if items:
                    # Get project ID and merchant center ID
                    project_id = list_data.get('project_id')
                    cloud_project_id = None
                    merchant_center_id = None
                    
                    # Get cloud project ID from client_projects collection
                    project_ref = firestore_client.collection('client_projects').document(project_id)
                    project_doc = project_ref.get()
                    if project_doc.exists:
                        project_data = project_doc.to_dict()
                        cloud_project_id = project_data.get('cloudProjectId')
                        
                        # Get merchant center ID for the country
                        country_code = list_data.get('country_code')
                        for mc in project_data.get('merchantCenters', []):
                            if mc.get('code') == country_code:
                                merchant_center_id = mc.get('merchantCenterId')
                                break
                    
                    # If we have cloud project ID and merchant center ID, fetch product details
                    if cloud_project_id and merchant_center_id:
                        # Extract all entity IDs
                        entity_ids = [item['entity_id'] for item in items]
                        
                        # Create a placeholder string for the IN clause
                        placeholders = ', '.join([f"'{entity_id}'" for entity_id in entity_ids])
                        
                        # Query for detailed product information
                        query = f"""
                        WITH main_bestseller AS (
                          SELECT DISTINCT
                            report_category_id,
                            category,
                            category_l2,
                            category_l3,
                            entity_id,
                            title,
                            country_code,
                            brand,
                            date_month,
                            rank AS avg_rank
                          FROM `s360-demand-sensing.ds_master_transformed_data.bestseller_monthly`
                          WHERE entity_id IN ({placeholders})
                          AND country_code = '{list_data.get('country_code')}'
                          ORDER BY date_month DESC
                        ),
                        client_data AS (
                          SELECT
                            COALESCE(products.feed_label, products.target_country) AS country_code,
                            mapping.entity_id,
                            products.availability
                          FROM
                            (
                              SELECT DISTINCT
                                product_id,
                                feed_label,
                                target_country,
                                availability
                              FROM `{cloud_project_id}.ds_raw_data.Products_{merchant_center_id}`
                              WHERE _PARTITIONTIME = (
                                SELECT MAX(_PARTITIONTIME)
                                FROM `{cloud_project_id}.ds_raw_data.Products_{merchant_center_id}`
                              )
                              AND channel = 'online'
                              AND feed_label IN ("{country_code}")
                            ) AS products
                          LEFT JOIN
                            (
                              SELECT
                                product_id,
                                entity_id
                              FROM `{cloud_project_id}.ds_raw_data.BestSellersEntityProductMapping_{merchant_center_id}`
                              WHERE _PARTITIONTIME = (
                                SELECT MAX(_PARTITIONTIME)
                                FROM `{cloud_project_id}.ds_raw_data.BestSellersEntityProductMapping_{merchant_center_id}`
                              )
                            ) AS mapping
                            ON mapping.product_id = products.product_id
                        )
                        SELECT DISTINCT
                          main_bestseller.report_category_id,
                          main_bestseller.category,
                          main_bestseller.category_l2,
                          main_bestseller.category_l3,
                          main_bestseller.entity_id,
                          main_bestseller.title,
                          main_bestseller.country_code,
                          main_bestseller.brand,
                          main_bestseller.date_month,
                          main_bestseller.avg_rank,
                          CASE 
                            WHEN client_data.availability IS NOT NULL THEN 'IN_STOCK'
                            ELSE 'NOT_IN_INVENTORY'
                          END AS product_inventory_status
                        FROM main_bestseller
                        LEFT JOIN client_data 
                        ON main_bestseller.entity_id = client_data.entity_id
                        AND main_bestseller.country_code = client_data.country_code
                        """
                        
                        # Execute the query
                        query_job = bigquery_client.query(query)
                        results = query_job.result()
                        
                        # Create a dictionary of product details by entity_id
                        product_details = {}
                        for row in results:
                            if row.entity_id not in product_details:
                                product_details[row.entity_id] = {
                                    "report_category_id": row.report_category_id,
                                    "category": row.category,
                                    "category_l2": row.category_l2,
                                    "category_l3": row.category_l3,
                                    "entity_id": row.entity_id,
                                    "title": row.title,
                                    "country_code": row.country_code,
                                    "brand": row.brand,
                                    "date_month": row.date_month.isoformat() if row.date_month else None,
                                    "avg_rank": row.avg_rank,
                                    "product_inventory_status": row.product_inventory_status
                                }
                        
                        # Add product details to items
                        for item in items:
                            entity_id = item['entity_id']
                            if entity_id in product_details:
                                item.update(product_details[entity_id])
                    
                    # Fetch GTINs for all entity IDs
                    # Create a placeholder string for the IN clause
                    entity_ids_placeholders = ', '.join([f"'{entity_id}'" for entity_id in entity_ids])
                    
                    # Query for GTINs
                    gtin_query = f"""
                    SELECT entity_id, gtin
                    FROM `s360-demand-sensing.ds_master_transformed_data.entity_gtins`
                    WHERE entity_id IN ({entity_ids_placeholders})
                    """
                    
                    # Execute the query
                    gtin_query_job = bigquery_client.query(gtin_query)
                    gtin_results = gtin_query_job.result()
                    
                    # Group GTINs by entity_id
                    gtins_by_entity = {}
                    for row in gtin_results:
                        if row.entity_id not in gtins_by_entity:
                            gtins_by_entity[row.entity_id] = []
                        if row.gtin:  # Only add non-None GTINs
                            gtins_by_entity[row.entity_id].append(row.gtin)
                    
                    # Add GTINs to items
                    for item in items:
                        entity_id = item['entity_id']
                        if entity_id in gtins_by_entity:
                            item['gtins'] = gtins_by_entity[entity_id]
                        else:
                            item['gtins'] = []
                
                return jsonify({
                    "success": True,
                    "items": items,
                    "list_metadata": {
                        "id": list_id,
                        "name": list_data.get('name'),
                        "description": list_data.get('description', ''),
                        "country_code": list_data.get('country_code'),
                        "project_id": list_data.get('project_id'),
                        "owner": list_data.get('owner'),
                        "shared_with": list_data.get('shared_with', []),
                        "is_owner": list_data.get('owner') == current_user
                    }
                })
        finally:
            conn.close()
    except Exception as e:
        print(f"Error fetching list items with GTINs: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Failed to fetch list items with GTINs: {str(e)}"
        }), 500

@app.route("/api/lists/<list_id>/items", methods=["POST"])
@token_required
def add_items_to_list(current_user, list_id):
    """Add products to a list"""
    try:
        data = request.json
        if not data or "items" not in data:
            return jsonify({"error": "No items provided"}), 400
            
        # Get the list document to check access
        list_ref = firestore_client.collection('user_lists').document(list_id)
        list_doc = list_ref.get()
        
        if not list_doc.exists:
            return jsonify({"error": "List not found"}), 404
            
        list_data = list_doc.to_dict()
        
        # Check if user has access to this list
        if list_data.get('owner') != current_user and current_user not in list_data.get('shared_with', []):
            return jsonify({"error": "You don't have permission to add to this list"}), 403
            
        # Process items to add
        items_to_add = data["items"]
        inserted_count = 0
        
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                for item in items_to_add:
                    if "entity_id" not in item:
                        continue
                        
                    # Insert into PostgreSQL
                    cursor.execute(
                        """
                        INSERT INTO user_lists (project_id, list_id, country_code, entity_id)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (project_id, list_id, country_code, entity_id) DO NOTHING
                        """,
                        (list_data.get('project_id'), list_id, list_data.get('country_code'), item["entity_id"])
                    )
                    
                    # Check if row was inserted
                    if cursor.rowcount > 0:
                        inserted_count += 1
                        
                # Update the list's updated_at timestamp
                list_ref.update({
                    "updated_at": firestore.SERVER_TIMESTAMP
                })
                
                return jsonify({
                    "success": True,
                    "message": f"Added {inserted_count} items to list successfully"
                })
        finally:
            conn.close()
    except Exception as e:
        print(f"Error adding items to list: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Failed to add items to list: {str(e)}"
        }), 500

@app.route("/api/lists/<list_id>/items/<entity_id>", methods=["DELETE"])
@token_required
def remove_item_from_list(current_user, list_id, entity_id):
    """Remove a product from a list"""
    try:
        # Get the list document to check access
        list_ref = firestore_client.collection('user_lists').document(list_id)
        list_doc = list_ref.get()
        
        if not list_doc.exists:
            return jsonify({"error": "List not found"}), 404
            
        list_data = list_doc.to_dict()
        
        # Check if user has access to this list
        if list_data.get('owner') != current_user and current_user not in list_data.get('shared_with', []):
            return jsonify({"error": "You don't have permission to remove from this list"}), 403
            
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                # Delete from PostgreSQL
                cursor.execute(
                    """
                    DELETE FROM user_lists 
                    WHERE list_id = %s AND entity_id = %s
                    """,
                    (list_id, entity_id)
                )
                
                # Update the list's updated_at timestamp
                list_ref.update({
                    "updated_at": firestore.SERVER_TIMESTAMP
                })
                
                return jsonify({
                    "success": True,
                    "message": "Item removed from list successfully"
                })
        finally:
            conn.close()
    except Exception as e:
        print(f"Error removing item from list: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Failed to remove item from list: {str(e)}"
        }), 500

@app.route("/api/lists/<list_id>/share", methods=["POST"])
@token_required
def share_list(current_user, list_id):
    """Share a list with other users"""
    try:
        data = request.json
        if not data or "emails" not in data:
            return jsonify({"error": "No emails provided"}), 400
            
        # Get the list document
        list_ref = firestore_client.collection('user_lists').document(list_id)
        list_doc = list_ref.get()
        
        if not list_doc.exists:
            return jsonify({"error": "List not found"}), 404
            
        list_data = list_doc.to_dict()
        
        # Only the owner can share the list
        if list_data.get('owner') != current_user:
            return jsonify({"error": "Only the list owner can share it"}), 403
            
        # Add emails to shared_with array
        shared_with = list_data.get('shared_with', [])
        new_emails = data["emails"]
        
        for email in new_emails:
            if email not in shared_with and email != list_data.get('owner'):
                shared_with.append(email)
        
        # Update the list document
        list_ref.update({
            "shared_with": shared_with,
            "updated_at": firestore.SERVER_TIMESTAMP
        })
        
        return jsonify({
            "success": True,
            "message": "List shared successfully",
            "shared_with": shared_with
        })
    except Exception as e:
        print(f"Error sharing list: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Failed to share list: {str(e)}"
        }), 500

@app.route("/api/lists/<list_id>/unshare", methods=["POST"])
@token_required
def unshare_list(current_user, list_id):
    """Remove a user's access to a list"""
    try:
        data = request.json
        if not data or "email" not in data:
            return jsonify({"error": "No email provided"}), 400
            
        # Get the list document
        list_ref = firestore_client.collection('user_lists').document(list_id)
        list_doc = list_ref.get()
        
        if not list_doc.exists:
            return jsonify({"error": "List not found"}), 404
            
        list_data = list_doc.to_dict()
        
        # Only the owner can unshare the list
        if list_data.get('owner') != current_user:
            return jsonify({"error": "Only the list owner can remove access"}), 403
            
        # Cannot remove the owner
        email_to_remove = data["email"]
        if email_to_remove == list_data.get('owner'):
            return jsonify({"error": "Cannot remove the list owner"}), 400
            
        # Remove email from shared_with array
        shared_with = list_data.get('shared_with', [])
        if email_to_remove in shared_with:
            shared_with.remove(email_to_remove)
        
        # Update the list document
        list_ref.update({
            "shared_with": shared_with,
            "updated_at": firestore.SERVER_TIMESTAMP
        })
        
        return jsonify({
            "success": True,
            "message": "User access removed successfully",
            "shared_with": shared_with
        })
    except Exception as e:
        print(f"Error removing list access: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Failed to remove list access: {str(e)}"
        }), 500

# Add a new API endpoint to get all list items for a project in one call
@app.route("/api/projects/<project_id>/list-items", methods=["GET"])
@token_required
def get_all_project_list_items(current_user, project_id):
    """Get all list items for all lists in a project in a single call"""
    try:
        # Get all lists for the user in this project
        lists_ref = firestore_client.collection('user_lists')
        owned_lists = list(lists_ref.where('owner', '==', current_user).where('project_id', '==', project_id).stream())
        shared_lists = list(lists_ref.where('shared_with', 'array_contains', current_user).where('project_id', '==', project_id).stream())
        
        all_lists = owned_lists + shared_lists
        
        # Get connection to PostgreSQL
        conn = get_db_connection()
        
        # Build result with all lists and their items
        result = {
            "lists": [],
            "itemsMap": {}
        }
        
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                for list_doc in all_lists:
                    list_data = list_doc.to_dict()
                    list_id = list_doc.id
                    
                    # Add list metadata to result
                    list_meta = {
                        "id": list_id,
                        "name": list_data.get("name"),
                        "description": list_data.get("description", ""),
                        "project_id": list_data.get("project_id"),
                        "country_code": list_data.get("country_code"),
                        "owner": list_data.get("owner"),
                        "shared_with": list_data.get("shared_with", []),
                        "is_owner": list_data.get("owner") == current_user
                    }
                    result["lists"].append(list_meta)
                    
                    # Get items for this list
                    cursor.execute(
                        "SELECT entity_id FROM user_lists WHERE list_id = %s",
                        (list_id,)
                    )
                    items = cursor.fetchall()
                    
                    # For each item, add this list to its entry in the map
                    for item in items:
                        entity_id = item['entity_id']
                        if entity_id not in result["itemsMap"]:
                            result["itemsMap"][entity_id] = []
                        
                        result["itemsMap"][entity_id].append({
                            "id": list_id,
                            "name": list_data.get("name")
                        })
            
            return jsonify({
                "success": True,
                "data": result
            })
        finally:
            conn.close()
            
    except Exception as e:
        print(f"Error fetching all list items: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Failed to fetch list items: {str(e)}"
        }), 500

@app.route("/api/lists/<list_id>/export", methods=["GET"])
@token_required
def export_list_to_csv(current_user, list_id):
    """Export list items to CSV"""
    try:
        # Get the list document to check access
        list_ref = firestore_client.collection('user_lists').document(list_id)
        list_doc = list_ref.get()
        
        if not list_doc.exists:
            return jsonify({"error": "List not found"}), 404
            
        list_data = list_doc.to_dict()
        
        # Check if user has access to this list
        if list_data.get('owner') != current_user and current_user not in list_data.get('shared_with', []):
            return jsonify({"error": "You don't have access to this list"}), 403
            
        # Get items from PostgreSQL
        conn = get_db_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                cursor.execute(
                    "SELECT * FROM user_lists WHERE list_id = %s",
                    (list_id,)
                )
                items = [dict(row) for row in cursor.fetchall()]
                
                # Get additional product details for each entity_id
                # If we have at least one item, fetch product details
                if items:
                    # Get project ID and merchant center ID
                    project_id = list_data.get('project_id')
                    cloud_project_id = None
                    merchant_center_id = None
                    
                    # Get cloud project ID from client_projects collection
                    project_ref = firestore_client.collection('client_projects').document(project_id)
                    project_doc = project_ref.get()
                    if project_doc.exists:
                        project_data = project_doc.to_dict()
                        cloud_project_id = project_data.get('cloudProjectId')
                        
                        # Get merchant center ID for the country
                        country_code = list_data.get('country_code')
                        for mc in project_data.get('merchantCenters', []):
                            if mc.get('code') == country_code:
                                merchant_center_id = mc.get('merchantCenterId')
                                break
                    
                    # If we have cloud project ID and merchant center ID, fetch product details
                    if cloud_project_id and merchant_center_id:
                        # Extract all entity IDs
                        entity_ids = [item['entity_id'] for item in items]
                        
                        # Create a placeholder string for the IN clause
                        placeholders = ', '.join([f"'{entity_id}'" for entity_id in entity_ids])
                        
                        # Query for detailed product information
                        query = f"""
                        WITH main_bestseller AS (
                          SELECT DISTINCT
                            report_category_id,
                            category,
                            category_l2,
                            category_l3,
                            entity_id,
                            title,
                            country_code,
                            brand,
                            date_month,
                            rank AS avg_rank
                          FROM `s360-demand-sensing.ds_master_transformed_data.bestseller_monthly`
                          WHERE entity_id IN ({placeholders})
                          AND country_code = '{list_data.get('country_code')}'
                          ORDER BY date_month DESC
                        ),
                        client_data AS (
                          SELECT
                            COALESCE(products.feed_label, products.target_country) AS country_code,
                            mapping.entity_id,
                            products.availability
                          FROM
                            (
                              SELECT DISTINCT
                                product_id,
                                feed_label,
                                target_country,
                                availability
                              FROM `{cloud_project_id}.ds_raw_data.Products_{merchant_center_id}`
                              WHERE _PARTITIONTIME = (
                                SELECT MAX(_PARTITIONTIME)
                                FROM `{cloud_project_id}.ds_raw_data.Products_{merchant_center_id}`
                              )
                              AND channel = 'online'
                              AND feed_label IN ("{country_code}")
                            ) AS products
                          LEFT JOIN
                            (
                              SELECT
                                product_id,
                                entity_id
                              FROM `{cloud_project_id}.ds_raw_data.BestSellersEntityProductMapping_{merchant_center_id}`
                              WHERE _PARTITIONTIME = (
                                SELECT MAX(_PARTITIONTIME)
                                FROM `{cloud_project_id}.ds_raw_data.BestSellersEntityProductMapping_{merchant_center_id}`
                              )
                            ) AS mapping
                            ON mapping.product_id = products.product_id
                        )
                        SELECT DISTINCT
                          main_bestseller.report_category_id,
                          main_bestseller.category,
                          main_bestseller.category_l2,
                          main_bestseller.category_l3,
                          main_bestseller.entity_id,
                          main_bestseller.title,
                          main_bestseller.country_code,
                          main_bestseller.brand,
                          main_bestseller.date_month,
                          main_bestseller.avg_rank,
                          CASE 
                            WHEN client_data.availability IS NOT NULL THEN 'IN_STOCK'
                            ELSE 'NOT_IN_INVENTORY'
                          END AS product_inventory_status
                        FROM main_bestseller
                        LEFT JOIN client_data 
                        ON main_bestseller.entity_id = client_data.entity_id
                        AND main_bestseller.country_code = client_data.country_code
                        """
                        
                        # Execute the query
                        query_job = bigquery_client.query(query)
                        results = query_job.result()
                        
                        # Create a dictionary of product details by entity_id
                        product_details = {}
                        for row in results:
                            if row.entity_id not in product_details:
                                product_details[row.entity_id] = {
                                    "report_category_id": row.report_category_id,
                                    "category": row.category,
                                    "category_l2": row.category_l2,
                                    "category_l3": row.category_l3,
                                    "entity_id": row.entity_id,
                                    "title": row.title,
                                    "country_code": row.country_code,
                                    "brand": row.brand,
                                    "date_month": row.date_month.isoformat() if row.date_month else None,
                                    "avg_rank": row.avg_rank,
                                    "product_inventory_status": row.product_inventory_status
                                }
                        
                        # Add product details to items
                        for item in items:
                            entity_id = item['entity_id']
                            if entity_id in product_details:
                                item.update(product_details[entity_id])
                    
                    # Fetch GTINs for all entity IDs
                    # Create a placeholder string for the IN clause
                    entity_ids_placeholders = ', '.join([f"'{entity_id}'" for entity_id in entity_ids])
                    
                    # Query for GTINs
                    gtin_query = f"""
                    SELECT entity_id, gtin
                    FROM `s360-demand-sensing.ds_master_transformed_data.entity_gtins`
                    WHERE entity_id IN ({entity_ids_placeholders})
                    """
                    
                    # Execute the query
                    gtin_query_job = bigquery_client.query(gtin_query)
                    gtin_results = gtin_query_job.result()
                    
                    # Group GTINs by entity_id
                    gtins_by_entity = {}
                    for row in gtin_results:
                        if row.entity_id not in gtins_by_entity:
                            gtins_by_entity[row.entity_id] = []
                        if row.gtin:  # Only add non-None GTINs
                            gtins_by_entity[row.entity_id].append(row.gtin)
                    
                    # Add GTINs to items
                    for item in items:
                        entity_id = item['entity_id']
                        if entity_id in gtins_by_entity:
                            item['gtins'] = gtins_by_entity[entity_id]
                        else:
                            item['gtins'] = []
                
                # Create CSV file in memory
                import io
                import csv
                
                # Define CSV headers
                headers = ["Entity ID", "Title", "Brand", "Category", "Rank", "In Assortment", "GTINs"]
                
                # Create a string IO buffer
                csv_buffer = io.StringIO()
                csv_writer = csv.writer(csv_buffer)
                
                # Write header row
                csv_writer.writerow(headers)
                
                # Write data rows
                for item in items:
                    gtins_str = "; ".join(item.get('gtins', [])) if item.get('gtins') else ""
                    
                    # Format the rank
                    rank = str(round(item.get('avg_rank'))) if item.get('avg_rank') else "N/A"
                    
                    # Format in_assortment status
                    in_assortment = "Yes" if item.get('product_inventory_status') == 'IN_STOCK' else "No"
                    
                    csv_writer.writerow([
                        item.get('entity_id', ''),
                        item.get('title', ''),
                        item.get('brand', ''),
                        item.get('category', ''),
                        rank,
                        in_assortment,
                        gtins_str
                    ])
                
                # Prepare the response
                response = Response(
                    csv_buffer.getvalue(),
                    mimetype="text/csv",
                    headers={
                        "Content-Disposition": f"attachment;filename={list_data.get('name', 'list')}_export.csv"
                    }
                )
                
                return response
        finally:
            conn.close()
    except Exception as e:
        print(f"Error exporting list to CSV: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Failed to export list: {str(e)}"
        }), 500

@app.route("/api/pricing", methods=["GET"])
@token_required
@project_access_required
def get_pricing_data(current_user, cloud_project_id = None):
    try:
        # Get query parameters for filtering
        # Brand filter parameters
        brand_filter = request.args.get('brand', None)
        brands = request.args.getlist('brands[]')  # Get multiple brands as array
        
        # Title filter parameter
        title_filter = request.args.get('title_filter', None)
        
        # Product type filter parameters
        product_type_l1 = request.args.get('product_type_l1', None)
        product_type_l1_values = request.args.getlist('product_type_l1[]')
        
        product_type_l2 = request.args.get('product_type_l2', None)
        product_type_l2_values = request.args.getlist('product_type_l2[]')
        
        product_type_l3 = request.args.get('product_type_l3', None)
        product_type_l3_values = request.args.getlist('product_type_l3[]')
        
        # Offer ID filter
        offer_id_filter = request.args.get('offer_id', None)
        
        # Price range filter
        min_price = request.args.get('min_price', None, type=float)
        max_price = request.args.get('max_price', None, type=float)
        
        # Get pagination parameters
        limit = request.args.get('limit', 20, type=int)
        offset = request.args.get('offset', 0, type=int)
        
        # Get sorting parameters
        sort_column = request.args.get('sort_column', 'potential_extra_clicks')
        sort_direction = request.args.get('sort_direction', 'desc').upper()
        
        # Get merchant center ID if provided
        merchant_center_id = request.args.get('merchant_center_id', None)
        
        # Validation: ensure we have the required parameters
        if not merchant_center_id or not cloud_project_id:
            return jsonify({
                "success": False,
                "error": "Missing required parameters: merchant_center_id and project_id"
            }), 400
        
        # Build filter clauses
        brand_filter_clause = ""
        if brands and len(brands) > 0:
            brand_strings = ["'" + brand.replace("'", "''") + "'" for brand in brands]
            brand_filter_clause = f"AND t.brand IN ({', '.join(brand_strings)})"
        elif brand_filter:
            safe_brand = brand_filter.replace("'", "''")
            brand_filter_clause = f"AND t.brand = '{safe_brand}'"
        
        # Title filter clause
        title_filter_clause = ""
        if title_filter:
            # Escape single quotes in the title filter to prevent SQL injection
            safe_title_filter = title_filter.replace("'", "''")
            title_filter_clause = f"AND LOWER(t.title) LIKE LOWER('%{safe_title_filter}%')"
        
        # Offer ID filter clause
        offer_id_filter_clause = ""
        if offer_id_filter:
            safe_offer_id = offer_id_filter.replace("'", "''")
            offer_id_filter_clause = f"AND t.offer_id = '{safe_offer_id}'"
        
        # Product type filter clauses
        product_type_l1_clause = ""
        if product_type_l1_values and len(product_type_l1_values) > 0:
            product_type_l1_strings = ["'" + pt.replace("'", "''") + "'" for pt in product_type_l1_values]
            product_type_l1_clause = f"AND t.product_type_l1 IN ({', '.join(product_type_l1_strings)})"
        elif product_type_l1:
            safe_product_type_l1 = product_type_l1.replace("'", "''")
            product_type_l1_clause = f"AND t.product_type_l1 = '{safe_product_type_l1}'"
        
        product_type_l2_clause = ""
        if product_type_l2_values and len(product_type_l2_values) > 0:
            product_type_l2_strings = ["'" + pt.replace("'", "''") + "'" for pt in product_type_l2_values]
            product_type_l2_clause = f"AND t.product_type_l2 IN ({', '.join(product_type_l2_strings)})"
        elif product_type_l2:
            safe_product_type_l2 = product_type_l2.replace("'", "''")
            product_type_l2_clause = f"AND t.product_type_l2 = '{safe_product_type_l2}'"
        
        product_type_l3_clause = ""
        if product_type_l3_values and len(product_type_l3_values) > 0:
            product_type_l3_strings = ["'" + pt.replace("'", "''") + "'" for pt in product_type_l3_values]
            product_type_l3_clause = f"AND t.product_type_l3 IN ({', '.join(product_type_l3_strings)})"
        elif product_type_l3:
            safe_product_type_l3 = product_type_l3.replace("'", "''")
            product_type_l3_clause = f"AND t.product_type_l3 = '{safe_product_type_l3}'"
        
        # Price range filter clause
        price_filter_clause = ""
        if min_price is not None:
            price_filter_clause += f"AND i.current_price >= {min_price}"
        if max_price is not None:
            price_filter_clause += f"AND i.current_price <= {max_price}"
        
        # Construct the SQL query based on the provided SQL template
        query = f"""
        WITH last7days AS (
          SELECT
            offer_id,
            title,
            brand,
            product_type_l1,
            product_type_l2,
            product_type_l3,
            SUM(clicks) AS last7days_clicks,
            SUM(impressions) AS last7days_impressions
          FROM `{cloud_project_id}.ds_raw_data.ProductPerformance_{merchant_center_id}`
          WHERE DATE(_PARTITIONTIME) BETWEEN DATE_SUB(CURRENT_DATE(), INTERVAL 6 DAY) AND CURRENT_DATE()
          GROUP BY
            offer_id, title, brand, product_type_l1, product_type_l2, product_type_l3
        ),
        latest_insights AS (
          SELECT
            offer_id,
            price.amount_micros / 1000000 AS current_price,
            suggested_price.amount_micros / 1000000 AS suggested_price,
            predicted_impressions_change_fraction,
            predicted_clicks_change_fraction,
            predicted_conversions_change_fraction
          FROM `{cloud_project_id}.ds_raw_data.PriceInsights_{merchant_center_id}`
          WHERE _PARTITIONTIME = (
            SELECT MAX(_PARTITIONTIME)
            FROM `{cloud_project_id}.ds_raw_data.PriceInsights_{merchant_center_id}`
          )
        )
        
        SELECT
          t.offer_id,
          t.title,
          t.brand,
          t.product_type_l1,
          t.product_type_l2,
          t.product_type_l3,
          t.last7days_clicks,
          t.last7days_impressions,
          i.current_price,
          i.suggested_price,
          i.predicted_impressions_change_fraction,
          i.predicted_clicks_change_fraction,
          i.predicted_conversions_change_fraction,
          ROUND(t.last7days_clicks * i.predicted_clicks_change_fraction,0) as potential_extra_clicks
        FROM last7days AS t
        LEFT JOIN latest_insights AS i
            ON lower(t.offer_id) = lower(i.offer_id)
        WHERE
          i.predicted_impressions_change_fraction is not null
          {brand_filter_clause}
          {title_filter_clause}
          {offer_id_filter_clause}
          {product_type_l1_clause}
          {product_type_l2_clause}
          {product_type_l3_clause}
          {price_filter_clause}
        ORDER BY {sort_column} {sort_direction}
        LIMIT {limit} OFFSET {offset}
        """

        # Count query for pagination and stats
        count_query = f"""
        WITH last7days AS (
          SELECT
            offer_id,
            title,
            brand,
            product_type_l1,
            product_type_l2,
            product_type_l3,
            SUM(clicks) AS last7days_clicks,
            SUM(impressions) AS last7days_impressions
          FROM `{cloud_project_id}.ds_raw_data.ProductPerformance_{merchant_center_id}`
          WHERE DATE(_PARTITIONTIME) BETWEEN DATE_SUB(CURRENT_DATE(), INTERVAL 6 DAY) AND CURRENT_DATE()
          GROUP BY
            offer_id, title, brand, product_type_l1, product_type_l2, product_type_l3
        ),
        latest_insights AS (
          SELECT
            offer_id,
            price.amount_micros / 1000000 AS current_price,
            suggested_price.amount_micros / 1000000 AS suggested_price,
            predicted_impressions_change_fraction,
            predicted_clicks_change_fraction,
            predicted_conversions_change_fraction
          FROM `{cloud_project_id}.ds_raw_data.PriceInsights_{merchant_center_id}`
          WHERE _PARTITIONTIME = (
            SELECT MAX(_PARTITIONTIME)
            FROM `{cloud_project_id}.ds_raw_data.PriceInsights_{merchant_center_id}`
          )
        )
        
        SELECT 
          COUNT(*) as total_count,
          COUNT(DISTINCT t.brand) as unique_brands_count,
          SUM(CASE WHEN i.current_price < i.suggested_price THEN 1 ELSE 0 END) as below_suggested_count,
          AVG(i.predicted_clicks_change_fraction) as avg_predicted_clicks_change
        FROM last7days AS t
        LEFT JOIN latest_insights AS i
          ON lower(t.offer_id) = lower(i.offer_id)
        WHERE
          i.predicted_impressions_change_fraction is not null
          {brand_filter_clause}
          {title_filter_clause}
          {offer_id_filter_clause}
          {product_type_l1_clause}
          {product_type_l2_clause}
          {product_type_l3_clause}
          {price_filter_clause}
        """

        # Execute the BQ query
        credentials_info = json.loads(BIGQUERY_SERVICE_ACCOUNT)
        credentials = service_account.Credentials.from_service_account_info(credentials_info)
        client = bigquery.Client(project=cloud_project_id, credentials=credentials)

        # Execute main and count queries concurrently
        with ThreadPoolExecutor(max_workers=2) as executor:
            query_future = executor.submit(client.query, query)
            count_future = executor.submit(client.query, count_query)
            
            # Get results
            query_job = query_future.result()
            count_job = count_future.result()
            
            # Process results
            results = query_job.result()
            count_results = count_job.result()
            
        count_row = list(count_results)[0]
        
        # Process the results
        pricing_data = []
        for row in results:
            # Format the data
            pricing_item = {
                "offer_id": row.offer_id,
                "title": row.title,
                "brand": row.brand,
                "product_type_l1": row.product_type_l1,
                "product_type_l2": row.product_type_l2,
                "product_type_l3": row.product_type_l3,
                "last7days_clicks": row.last7days_clicks,
                "last7days_impressions": row.last7days_impressions,
                "current_price": row.current_price,
                "suggested_price": row.suggested_price,
                "predicted_impressions_change_fraction": row.predicted_impressions_change_fraction,
                "predicted_clicks_change_fraction": row.predicted_clicks_change_fraction,
                "predicted_conversions_change_fraction": row.predicted_conversions_change_fraction,
                "potential_extra_clicks": row.potential_extra_clicks
            }
            pricing_data.append(pricing_item)
        
        # Process count results
        total_count = count_row.total_count
        unique_brands_count = count_row.unique_brands_count
        below_suggested_count = count_row.below_suggested_count
        avg_predicted_clicks_change = count_row.avg_predicted_clicks_change
        
        # Get min and max price for range slider
        min_max_price_query = f"""
        WITH latest_insights AS (
          SELECT
            offer_id,
            price.amount_micros / 1000000 AS current_price
          FROM `{cloud_project_id}.ds_raw_data.PriceInsights_{merchant_center_id}`
          WHERE _PARTITIONTIME = (
            SELECT MAX(_PARTITIONTIME)
            FROM `{cloud_project_id}.ds_raw_data.PriceInsights_{merchant_center_id}`
          )
        )
        
        SELECT 
          MIN(current_price) as min_price,
          MAX(current_price) as max_price
        FROM latest_insights
        WHERE current_price > 0
        """
        
        min_max_job = client.query(min_max_price_query)
        min_max_results = min_max_job.result()
        min_max_row = list(min_max_results)[0]
        
        # Get distinct product types for filters
        product_types_query = f"""
        SELECT DISTINCT
          product_type_l1,
          product_type_l2,
          product_type_l3
        FROM `{cloud_project_id}.ds_raw_data.ProductPerformance_{merchant_center_id}`
        WHERE DATE(_PARTITIONTIME) BETWEEN DATE_SUB(CURRENT_DATE(), INTERVAL 6 DAY) AND CURRENT_DATE()
        ORDER BY product_type_l1, product_type_l2, product_type_l3
        """
        
        product_types_job = client.query(product_types_query)
        product_types_results = product_types_job.result()

        product_types = {}
        for row in product_types_results:
            if row.product_type_l1 not in product_types:
                product_types[row.product_type_l1] = {}
            
            if row.product_type_l2 not in product_types[row.product_type_l1]:
                product_types[row.product_type_l1][row.product_type_l2] = []
            
            if row.product_type_l3:
                product_types[row.product_type_l1][row.product_type_l2].append(row.product_type_l3)
        
        # Prepare the response
        response = {
            "success": True,
            "pricing_data": pricing_data,
            "total": total_count,
            "stats": {
                "total_products": total_count,
                "unique_brands": unique_brands_count,
                "below_suggested_price": below_suggested_count,
                "avg_predicted_clicks_change": avg_predicted_clicks_change
            }
        }
        
        return jsonify(response)
        
    except Exception as e:
        print(f"Error fetching pricing data: {str(e)}")
        traceback.print_exc()
        return jsonify({"success": False, "error": f"Failed to fetch pricing data: {str(e)}"}), 500




# ----- Stream Management API Routes -----

@app.route("/api/pricing/filters", methods=["GET"])
@token_required
@project_access_required
def get_pricing_filters(current_user, cloud_project_id = None):
    """Get filter options for pricing data (product types, brands, price range)"""
    try:
        from concurrent.futures import ThreadPoolExecutor
        
        # Get merchant center ID if provided
        merchant_center_id = request.args.get('merchant_center_id', None)
        
        # Validation: ensure we have the required parameters
        if not merchant_center_id or not cloud_project_id:
            return jsonify({
                "success": False,
                "error": "Missing required parameters: merchant_center_id and project_id"
            }), 400
        
        # Create BigQuery client
        credentials_info = json.loads(BIGQUERY_SERVICE_ACCOUNT)
        credentials = service_account.Credentials.from_service_account_info(credentials_info)
        client = bigquery.Client(project=cloud_project_id, credentials=credentials)
        
        # Define query for min/max price
        min_max_price_query = f"""
        WITH latest_insights AS (
          SELECT
            offer_id,
            price.amount_micros / 1000000 AS current_price
          FROM `{cloud_project_id}.ds_raw_data.PriceInsights_{merchant_center_id}`
          WHERE _PARTITIONTIME = (
            SELECT MAX(_PARTITIONTIME)
            FROM `{cloud_project_id}.ds_raw_data.PriceInsights_{merchant_center_id}`
          )
        )
        
        SELECT 
          MIN(current_price) as min_price,
          MAX(current_price) as max_price
        FROM latest_insights
        WHERE current_price > 0
        """
        
        # Define query for product types
        product_types_query = f"""
        SELECT DISTINCT
          product_type_l1,
          product_type_l2,
          product_type_l3
        FROM `{cloud_project_id}.ds_raw_data.ProductPerformance_{merchant_center_id}`
        WHERE DATE(_PARTITIONTIME) BETWEEN DATE_SUB(CURRENT_DATE(), INTERVAL 6 DAY) AND CURRENT_DATE()
        ORDER BY product_type_l1, product_type_l2, product_type_l3
        """
        
        # Define query for brands
        brands_query = f"""
        SELECT DISTINCT brand
        FROM `{cloud_project_id}.ds_raw_data.ProductPerformance_{merchant_center_id}`
        WHERE DATE(_PARTITIONTIME) BETWEEN DATE_SUB(CURRENT_DATE(), INTERVAL 6 DAY) AND CURRENT_DATE()
        AND brand IS NOT NULL AND brand != ''
        ORDER BY brand
        """
        
        # Execute all queries concurrently
        with ThreadPoolExecutor(max_workers=3) as executor:
            min_max_future = executor.submit(client.query, min_max_price_query)
            product_types_future = executor.submit(client.query, product_types_query)
            brands_future = executor.submit(client.query, brands_query)
            
            # Get results from all queries
            min_max_job = min_max_future.result()
            product_types_job = product_types_future.result()
            brands_job = brands_future.result()
            
            # Process results
            min_max_results = min_max_job.result()
            product_types_results = product_types_job.result()
            brands_results = brands_job.result()
        
        # Process min_max results
        min_max_row = list(min_max_results)[0]
        
        # Process product types results
        product_types = {}
        for row in product_types_results:
            if row.product_type_l1 not in product_types:
                product_types[row.product_type_l1] = {}
            
            if row.product_type_l2 not in product_types[row.product_type_l1]:
                product_types[row.product_type_l1][row.product_type_l2] = []
            
            if row.product_type_l3:
                product_types[row.product_type_l1][row.product_type_l2].append(row.product_type_l3)
        
        # Process brands results
        brands = [row.brand for row in brands_results]
        
        # Prepare the response
        response = {
            "success": True,
            "price_range": {
                "min_price": min_max_row.min_price,
                "max_price": min_max_row.max_price
            },
            "product_types": product_types,
            "brands": brands
        }
        
        return jsonify(response)
        
    except Exception as e:
        print(f"Error fetching pricing filters: {str(e)}")
        traceback.print_exc()
        return jsonify({"success": False, "error": f"Failed to fetch pricing filters: {str(e)}"}), 500

@app.route("/api/streams", methods=["GET"])
@token_required
def get_streams(current_user):
    """Get all streams for a project that the user has access to"""
    try:
        # Get project_id parameter
        project_id = request.args.get('project_id', None)
        if not project_id:
            return jsonify({"error": "Missing project_id parameter"}), 400
            
        # Get streams from Firestore
        streams_ref = firestore_client.collection('pricing_streams')
        
        # Get streams owned by the user for this project
        user_streams = list(streams_ref.where('created_by', '==', current_user)
                                      .where('project_id', '==', project_id)
                                      .stream())
        
        # Format the streams for response
        streams = []
        for stream_doc in user_streams:
            stream_data = stream_doc.to_dict()
            stream_data['id'] = stream_doc.id
            stream_data['public_url'] = f"{request.host_url}public/stream/{stream_doc.id}"
            streams.append(stream_data)
        
        return jsonify({
            "success": True,
            "streams": streams
        })
    except Exception as e:
        print(f"Error fetching streams: {str(e)}")
        return jsonify({"success": False, "error": f"Failed to fetch streams: {str(e)}"}), 500

@app.route("/api/streams", methods=["POST"])
@token_required
def create_stream(current_user):
    """Create a new pricing stream"""
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        required_fields = ["name", "project_id", "merchant_center_id", "filters"]
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing required field: {field}"}), 400
        
        # Create new stream document
        new_stream = {
            "name": data["name"],
            "description": data.get("description", ""),
            "project_id": data["project_id"],
            "merchant_center_id": data["merchant_center_id"],
            "filters": data["filters"],
            "created_by": current_user,
            "created_at": firestore.SERVER_TIMESTAMP,
            "updated_at": firestore.SERVER_TIMESTAMP
        }
        
        # Add to Firestore
        stream_ref = firestore_client.collection('pricing_streams').document()
        stream_ref.set(new_stream)
        
        # Get the stream with server timestamp
        stream_doc = stream_ref.get()
        stream_data = stream_doc.to_dict()
        stream_data['id'] = stream_ref.id
        stream_data['public_url'] = f"{request.host_url}public/stream/{stream_ref.id}"
        
        return jsonify({
            "success": True,
            "message": "Stream created successfully",
            "stream": stream_data
        })
    except Exception as e:
        print(f"Error creating stream: {str(e)}")
        return jsonify({"success": False, "error": f"Failed to create stream: {str(e)}"}), 500

@app.route("/api/streams/<stream_id>", methods=["PUT"])
@token_required
def update_stream(current_user, stream_id):
    """Update a stream"""
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        # Get the stream document
        stream_ref = firestore_client.collection('pricing_streams').document(stream_id)
        stream_doc = stream_ref.get()
        
        if not stream_doc.exists:
            return jsonify({"error": "Stream not found"}), 404
            
        stream_data = stream_doc.to_dict()
        
        # Only the creator can update the stream
        if stream_data.get('created_by') != current_user:
            return jsonify({"error": "You don't have permission to update this stream"}), 403
            
        # Fields that are allowed to be updated
        allowed_fields = ["name", "description", "filters", "merchant_center_id"]
        
        # Create update dictionary
        update_data = {
            "updated_at": firestore.SERVER_TIMESTAMP
        }
        
        # Add fields from request data
        for field in allowed_fields:
            if field in data:
                update_data[field] = data[field]
        
        # Update the stream document
        stream_ref.update(update_data)
        
        # Get the updated document
        updated_doc = stream_ref.get()
        updated_data = updated_doc.to_dict()
        updated_data['id'] = stream_id
        updated_data['public_url'] = f"{request.host_url}public/stream/{stream_id}"
        
        return jsonify({
            "success": True,
            "message": "Stream updated successfully",
            "stream": updated_data
        })
    except Exception as e:
        print(f"Error updating stream: {str(e)}")
        return jsonify({"success": False, "error": f"Failed to update stream: {str(e)}"}), 500

@app.route("/api/streams/<stream_id>", methods=["DELETE"])
@token_required
def delete_stream(current_user, stream_id):
    """Delete a stream"""
    try:
        # Get the stream document
        stream_ref = firestore_client.collection('pricing_streams').document(stream_id)
        stream_doc = stream_ref.get()
        
        if not stream_doc.exists:
            return jsonify({"error": "Stream not found"}), 404
            
        stream_data = stream_doc.to_dict()
        
        # Only the creator can delete the stream
        if stream_data.get('created_by') != current_user:
            return jsonify({"error": "You don't have permission to delete this stream"}), 403
            
        # Delete the stream
        stream_ref.delete()
        
        return jsonify({
            "success": True,
            "message": "Stream deleted successfully"
        })
    except Exception as e:
        print(f"Error deleting stream: {str(e)}")
        return jsonify({"success": False, "error": f"Failed to delete stream: {str(e)}"}), 500

# Public XML endpoint for streams
@app.route("/public/stream/<stream_id>", methods=["GET"])
def get_public_stream(stream_id):
    """Public endpoint to get stream data as XML"""
    try:
        # Get the stream document
        stream_ref = firestore_client.collection('pricing_streams').document(stream_id)
        stream_doc = stream_ref.get()
        
        if not stream_doc.exists:
            return jsonify({"error": "Stream not found"}), 404
            
        stream_data = stream_doc.to_dict()
        
        # Extract stream information
        project_id = stream_data.get('project_id')
        merchant_center_id = stream_data.get('merchant_center_id')
        filters = stream_data.get('filters', {})
        
        # Get the cloud project ID
        project_ref = firestore_client.collection('client_projects').document(project_id)
        project_doc = project_ref.get()
        
        if not project_doc.exists:
            return jsonify({"error": "Project not found"}), 404
            
        project_data = project_doc.to_dict()
        cloud_project_id = project_data.get('cloudProjectId')
        
        if not cloud_project_id:
            return jsonify({"error": "Invalid project configuration"}), 500
        
        # Build filter clauses for the query
        
        # Brand filter
        brand_filter_clause = ""
        brands = filters.get('brands', [])
        brand = filters.get('brand')
        
        if brands and len(brands) > 0:
            brand_strings = ["'" + brand.replace("'", "''") + "'" for brand in brands]
            brand_filter_clause = f"AND t.brand IN ({', '.join(brand_strings)})"
        elif brand:
            safe_brand = brand.replace("'", "''")
            brand_filter_clause = f"AND t.brand = '{safe_brand}'"
        
        # Title filter
        title_filter_clause = ""
        title_filter = filters.get('title_filter')
        if title_filter:
            safe_title_filter = title_filter.replace("'", "''")
            title_filter_clause = f"AND LOWER(t.title) LIKE LOWER('%{safe_title_filter}%')"
        
        # Offer ID filter
        offer_id_filter_clause = ""
        offer_id_filter = filters.get('offer_id')
        if offer_id_filter:
            safe_offer_id = offer_id_filter.replace("'", "''")
            offer_id_filter_clause = f"AND t.offer_id = '{safe_offer_id}'"
        
        # Product type filter clauses
        product_type_l1_clause = ""
        product_type_l1 = filters.get('product_type_l1')
        product_type_l1_values = filters.get('selectedProductTypeL1', [])
        
        if product_type_l1_values and len(product_type_l1_values) > 0:
            product_type_l1_strings = ["'" + pt.replace("'", "''") + "'" for pt in product_type_l1_values]
            product_type_l1_clause = f"AND t.product_type_l1 IN ({', '.join(product_type_l1_strings)})"
        elif product_type_l1:
            safe_product_type_l1 = product_type_l1.replace("'", "''")
            product_type_l1_clause = f"AND t.product_type_l1 = '{safe_product_type_l1}'"
        
        product_type_l2_clause = ""
        product_type_l2 = filters.get('product_type_l2')
        product_type_l2_values = filters.get('selectedProductTypeL2', [])
        
        if product_type_l2_values and len(product_type_l2_values) > 0:
            product_type_l2_strings = ["'" + pt.replace("'", "''") + "'" for pt in product_type_l2_values]
            product_type_l2_clause = f"AND t.product_type_l2 IN ({', '.join(product_type_l2_strings)})"
        elif product_type_l2:
            safe_product_type_l2 = product_type_l2.replace("'", "''")
            product_type_l2_clause = f"AND t.product_type_l2 = '{safe_product_type_l2}'"
        
        product_type_l3_clause = ""
        product_type_l3 = filters.get('product_type_l3')
        product_type_l3_values = filters.get('selectedProductTypeL3', [])
        
        if product_type_l3_values and len(product_type_l3_values) > 0:
            product_type_l3_strings = ["'" + pt.replace("'", "''") + "'" for pt in product_type_l3_values]
            product_type_l3_clause = f"AND t.product_type_l3 IN ({', '.join(product_type_l3_strings)})"
        elif product_type_l3:
            safe_product_type_l3 = product_type_l3.replace("'", "''")
            product_type_l3_clause = f"AND t.product_type_l3 = '{safe_product_type_l3}'"
        
        # Price range filter
        price_filter_clause = ""
        min_price = filters.get('minPrice')
        max_price = filters.get('maxPrice')
        
        if min_price is not None:
            price_filter_clause += f"AND i.current_price >= {min_price} "
        if max_price is not None:
            price_filter_clause += f"AND i.current_price <= {max_price}"
        
        # Construct the SQL query
        query = f"""
        WITH last7days AS (
          SELECT
            offer_id,
            title,
            brand,
            product_type_l1,
            product_type_l2,
            product_type_l3,
            SUM(clicks) AS last7days_clicks,
            SUM(impressions) AS last7days_impressions
          FROM `{cloud_project_id}.ds_raw_data.ProductPerformance_{merchant_center_id}`
          WHERE DATE(_PARTITIONTIME) BETWEEN DATE_SUB(CURRENT_DATE(), INTERVAL 6 DAY) AND CURRENT_DATE()
          GROUP BY
            offer_id, title, brand, product_type_l1, product_type_l2, product_type_l3
        ),
        latest_insights AS (
          SELECT
            offer_id,
            price.amount_micros / 1000000 AS current_price,
            suggested_price.amount_micros / 1000000 AS suggested_price,
            predicted_impressions_change_fraction,
            predicted_clicks_change_fraction,
            predicted_conversions_change_fraction
          FROM `{cloud_project_id}.ds_raw_data.PriceInsights_{merchant_center_id}`
          WHERE _PARTITIONTIME = (
            SELECT MAX(_PARTITIONTIME)
            FROM `{cloud_project_id}.ds_raw_data.PriceInsights_{merchant_center_id}`
          )
        )
        
        SELECT
          t.offer_id,
          t.title,
          t.brand,
          t.product_type_l1,
          t.product_type_l2,
          t.product_type_l3,
          t.last7days_clicks,
          t.last7days_impressions,
          i.current_price,
          i.suggested_price,
          i.predicted_impressions_change_fraction,
          i.predicted_clicks_change_fraction,
          i.predicted_conversions_change_fraction,
          ROUND(t.last7days_clicks * i.predicted_clicks_change_fraction,0) as potential_extra_clicks
        FROM last7days AS t
        LEFT JOIN latest_insights AS i
          ON LOWER(t.offer_id) = LOWER(i.offer_id)
        WHERE
          i.predicted_impressions_change_fraction is not null
          {brand_filter_clause}
          {title_filter_clause}
          {offer_id_filter_clause}
          {product_type_l1_clause}
          {product_type_l2_clause}
          {product_type_l3_clause}
          {price_filter_clause}
        ORDER BY potential_extra_clicks DESC
        """

        # Execute the BQ query
        # FIX: Use service account credentials here, just like in other routes
        credentials_info = json.loads(BIGQUERY_SERVICE_ACCOUNT)
        credentials = service_account.Credentials.from_service_account_info(credentials_info)
        client = bigquery.Client(project=cloud_project_id, credentials=credentials)
        
        query_job = client.query(query)
        results = query_job.result()
        
        # Process the results and create XML
        from xml.etree.ElementTree import Element, SubElement, tostring
        import xml.dom.minidom
        
        # Create the root element as RSS
        root = Element('rss')
        root.set('xmlns:g', 'http://base.google.com/ns/1.0')
        root.set('version', '2.0')
        
        # Create channel element
        channel = SubElement(root, 'channel')
        
        # Get project name for the title
        project_name = "Unknown Project"
        try:
            project_ref = firestore_client.collection('client_projects').document(project_id)
            project_doc = project_ref.get()
            if project_doc.exists:
                project_data = project_doc.to_dict()
                project_name = project_data.get('name', 'Unknown Project')
        except Exception as e:
            print(f"Error getting project name: {str(e)}")
        
        # Add channel metadata
        SubElement(channel, 'title').text = f"s360 Demand Sense {project_name}"
        SubElement(channel, 'link').text = "https://ds.s360digital.com/"
        SubElement(channel, 'description').text = f"Price optimization data stream: {stream_data.get('name', '')}"
        SubElement(channel, 'lastBuildDate').text = datetime.now().strftime("%a, %d %b %Y %H:%M:%S %z")
        
        # Add each product as an item
        for row in results:
            item = SubElement(channel, 'item')
            
            # Add product details
            SubElement(item, 'offerId').text = row.offer_id if row.offer_id else ''
            SubElement(item, 'title').text = row.title if row.title else ''
            SubElement(item, 'brand').text = row.brand if row.brand else ''
            
            # Add product types
            product_types = SubElement(item, 'productTypes')
            SubElement(product_types, 'level1').text = row.product_type_l1 if row.product_type_l1 else ''
            SubElement(product_types, 'level2').text = row.product_type_l2 if row.product_type_l2 else ''
            SubElement(product_types, 'level3').text = row.product_type_l3 if row.product_type_l3 else ''
            
            # Add performance data
            performance = SubElement(item, 'performance')
            SubElement(performance, 'last7daysClicks').text = str(row.last7days_clicks) if row.last7days_clicks else '0'
            SubElement(performance, 'last7daysImpressions').text = str(row.last7days_impressions) if row.last7days_impressions else '0'
            
            # Add pricing data
            pricing = SubElement(item, 'pricing')
            SubElement(pricing, 'currentPrice').text = f"{row.current_price:.2f}" if row.current_price else '0'
            SubElement(pricing, 'suggestedPrice').text = f"{row.suggested_price:.2f}" if row.suggested_price else '0'
            
            # Add predictions
            predictions = SubElement(item, 'predictions')
            
            if row.predicted_clicks_change_fraction:
                click_change = row.predicted_clicks_change_fraction * 100
                SubElement(predictions, 'clickChangePercent').text = f"{click_change:.2f}"
            else:
                SubElement(predictions, 'clickChangePercent').text = "0"
                
            if row.predicted_conversions_change_fraction:
                conversion_change = row.predicted_conversions_change_fraction * 100
                SubElement(predictions, 'conversionChangePercent').text = f"{conversion_change:.2f}"
            else:
                SubElement(predictions, 'conversionChangePercent').text = "0"
                
            SubElement(predictions, 'potentialExtraClicks').text = str(row.potential_extra_clicks) if row.potential_extra_clicks else '0'
        
        # Convert to pretty XML
        rough_string = tostring(root, 'utf-8')
        reparsed = xml.dom.minidom.parseString(rough_string)
        pretty_xml = reparsed.toprettyxml(indent="  ")
        
        # Create XML response
        response = make_response(pretty_xml)
        response.headers['Content-Type'] = 'application/xml'
        
        # Update access timestamp in Firestore
        stream_ref.update({
            "last_accessed": firestore.SERVER_TIMESTAMP
        })
        
        return response
        
    except Exception as e:
        print(f"Error generating stream XML: {str(e)}")
        return jsonify({"error": f"Failed to generate stream XML: {str(e)}"}), 500

@app.route("/api/user/filter-presets", methods=["GET"])
@token_required
def get_user_filter_presets(current_user):
    """Get the filter presets for the current user"""
    user_email = current_user  # current_user is already the email string
    
    try:
        # Get the user document from Firestore
        user_ref = firestore_client.collection('users').document(user_email)
        user_doc = user_ref.get()
        
        if not user_doc.exists:
            return jsonify({
                "success": False,
                "error": "User document not found"
            }), 404
        
        # Get the filter_presets array from the user document (default to empty list)
        user_data = user_doc.to_dict()
        filter_presets = user_data.get('filter_presets', [])
        
        return jsonify({
            "success": True,
            "data": {
                "presets": filter_presets
            }
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route("/api/user/filter-presets", methods=["POST"])
@token_required
def save_user_filter_preset(current_user):
    """Save a new filter preset for the current user"""
    user_email = current_user  # current_user is already the email string
    
    try:
        # Get request data
        data = request.get_json()
        
        if not data or not data.get('name') or not data.get('filters'):
            return jsonify({
                "success": False,
                "error": "Missing required fields (name, filters)"
            }), 400
        
        preset_name = data.get('name')
        preset_filters = data.get('filters')
        project_id = data.get('project_id')
        
        if not project_id:
            return jsonify({
                "success": False,
                "error": "Missing project_id field"
            }), 400
        
        # Log the received data for debugging
        print(f"Saving filter preset for user: {user_email}")
        print(f"Project ID: {project_id}")
        print(f"Preset name: {preset_name}")
        
        # Ensure preset_filters is serializable by converting to dict if it's not already
        # Also ensure all values in the filters are of simple types that Firestore can handle
        if isinstance(preset_filters, dict):
            # Make a clean copy with only the necessary filter fields
            clean_filters = {
                # Arrays for multiselect filters (ensure they're lists, not undefined)
                'selectedMonths': preset_filters.get('selectedMonths', []),
                'selectedCategories': preset_filters.get('selectedCategories', []),
                'selectedCategoryL2': preset_filters.get('selectedCategoryL2', []),
                'selectedCategoryL3': preset_filters.get('selectedCategoryL3', []),
                'selectedBrands': preset_filters.get('selectedBrands', []),
                'selectedCountries': preset_filters.get('selectedCountries', []),
                'selectedInventoryStatuses': preset_filters.get('selectedInventoryStatuses', []),
                
                # String filters (ensure they're strings, not null)
                'categoryFilter': preset_filters.get('categoryFilter', ''),
                'titleFilter': preset_filters.get('titleFilter', ''),
                'activeList': preset_filters.get('activeList', ''),
                
                # Mode settings
                'timePeriodMode': preset_filters.get('timePeriodMode', 'strict'),
                
                # Search fields
                'categorySearch': preset_filters.get('categorySearch', ''),
                'brandSearch': preset_filters.get('brandSearch', ''),
                'countrySearch': preset_filters.get('countrySearch', '')
            }
            preset_filters = clean_filters
        
        # Get the user document from Firestore
        user_ref = firestore_client.collection('users').document(user_email)
        user_doc = user_ref.get()
        
        if not user_doc.exists:
            return jsonify({
                "success": False,
                "error": "User document not found"
            }), 404
        
        # Generate a unique ID for the preset
        preset_id = str(uuid.uuid4())
        
        # Use current timestamp instead of SERVER_TIMESTAMP
        current_time = datetime.now().isoformat()
        
        # Create new preset object
        new_preset = {
            'id': preset_id,
            'name': preset_name,
            'filters': preset_filters,
            'project_id': project_id,
            'created_at': current_time  # Use string timestamp instead of SERVER_TIMESTAMP
        }
        
        # Instead of using ArrayUnion which might have issues with complex objects,
        # get current presets, append the new one, and update the whole array
        user_data = user_doc.to_dict()
        current_presets = user_data.get('filter_presets', [])
        current_presets.append(new_preset)
        
        # Update the user document with the new array of presets
        user_ref.update({
            'filter_presets': current_presets
        })
        
        return jsonify({
            "success": True,
            "data": {
                "preset": new_preset
            }
        })
    except Exception as e:
        print(f"Error saving filter preset: {str(e)}")
        print(f"Error details: {traceback.format_exc()}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route("/api/user/filter-presets/<preset_id>", methods=["DELETE"])
@token_required
def delete_user_filter_preset(current_user, preset_id):
    """Delete a filter preset for the current user"""
    user_email = current_user  # current_user is already the email string
    
    try:
        # Get the user document from Firestore
        user_ref = firestore_client.collection('users').document(user_email)
        user_doc = user_ref.get()
        
        if not user_doc.exists:
            return jsonify({
                "success": False,
                "error": "User document not found"
            }), 404
        
        # Get the current filter_presets array
        user_data = user_doc.to_dict()
        filter_presets = user_data.get('filter_presets', [])
        
        # Find the preset to delete
        preset_to_delete = None
        for preset in filter_presets:
            if preset.get('id') == preset_id:
                preset_to_delete = preset
                break
        
        if not preset_to_delete:
            return jsonify({
                "success": False,
                "error": f"Preset with ID {preset_id} not found"
            }), 404
        
        # Remove the preset from the array
        updated_presets = [p for p in filter_presets if p.get('id') != preset_id]
        
        # Update the user document
        user_ref.update({
            'filter_presets': updated_presets
        })
        
        return jsonify({
            "success": True,
            "message": f"Preset {preset_id} deleted successfully"
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route("/api/admin/login-activity", methods=["GET"])
@token_required_admin
def get_login_activity(current_user):
    """Get login activity data for admin dashboard visualizations"""
    try:
        # Get optional date range parameters
        start_date = request.args.get('start_date', None)
        end_date = request.args.get('end_date', None)
        
        # Get domain filters
        domains = request.args.getlist('domains[]')
        emails = request.args.getlist('emails[]')
        exclude_s360 = request.args.get('exclude_s360', 'false').lower() == 'true'
        
        # Build query with optional date filtering
        query = """
        WITH login_entries AS (
            SELECT 
                date,
                mail,
                name,
                REGEXP_EXTRACT(mail, r'@(.+)$') as domain
            FROM `s360-demand-sensing.web_app_logs.web_app_logins`
        """
        
        # Add date filters if provided
        where_clauses = []
        if start_date:
            where_clauses.append(f"DATE(date) >= '{start_date}'")
        if end_date:
            where_clauses.append(f"DATE(date) <= '{end_date}'")
            
        # Add domain filters
        if domains:
            domains_str = ", ".join([f"'{domain}'" for domain in domains])
            where_clauses.append(f"REGEXP_EXTRACT(mail, r'@(.+)$') IN ({domains_str})")
            
        # Add email filters
        if emails:
            emails_str = ", ".join([f"'{email}'" for email in emails])
            where_clauses.append(f"mail IN ({emails_str})")
        
        # Add s360 exclusion
        if exclude_s360:
            where_clauses.append("REGEXP_EXTRACT(mail, r'@(.+)$') != 's360digital.com'")
            
        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)
            
        # Finish the CTE
        query += """
        )
        SELECT 
            date as login_date,
            mail,
            name,
            domain,
            COUNT(*) as login_count
        FROM login_entries
        GROUP BY login_date, mail, name, domain
        ORDER BY login_date DESC, login_count DESC
        """
        
        # Daily logins over time
        daily_query = """
        WITH logins AS (
            SELECT 
                DATE(date) as login_date,
                mail,
                REGEXP_EXTRACT(mail, r'@(.+)$') as domain
            FROM `s360-demand-sensing.web_app_logs.web_app_logins`
        """
        
        if where_clauses:
            daily_query += " WHERE " + " AND ".join(where_clauses)
            
        daily_query += """
        )
        SELECT 
            login_date,
            COUNT(DISTINCT mail) as unique_users,
            COUNT(*) as total_logins
        FROM logins
        GROUP BY login_date
        ORDER BY login_date
        """
        
        # Domain-based logins
        domain_query = """
        WITH logins AS (
            SELECT 
                mail,
                REGEXP_EXTRACT(mail, r'@(.+)$') as domain
            FROM `s360-demand-sensing.web_app_logs.web_app_logins`
        """
        
        if where_clauses:
            domain_query += " WHERE " + " AND ".join(where_clauses)
            
        domain_query += """
        )
        SELECT 
            domain,
            COUNT(DISTINCT mail) as unique_users,
            COUNT(*) as total_logins
        FROM logins
        GROUP BY domain
        ORDER BY total_logins DESC
        LIMIT 10
        """
        
        # Top users by login count
        top_users_query = """
        WITH logins AS (
            SELECT 
                mail,
                name,
                REGEXP_EXTRACT(mail, r'@(.+)$') as domain
            FROM `s360-demand-sensing.web_app_logs.web_app_logins`
        """
        
        if where_clauses:
            top_users_query += " WHERE " + " AND ".join(where_clauses)
            
        top_users_query += """
        )
        SELECT 
            mail,
            name,
            COUNT(*) as login_count
        FROM logins
        GROUP BY mail, name
        ORDER BY login_count DESC
        LIMIT 10
        """
        
        # Get all domains for filtering
        all_domains_query = """
        SELECT DISTINCT 
            REGEXP_EXTRACT(mail, r'@(.+)$') as domain,
            COUNT(DISTINCT mail) as user_count
        FROM `s360-demand-sensing.web_app_logs.web_app_logins`
        GROUP BY domain
        ORDER BY user_count DESC
        """
        
        # Get all emails for filtering
        all_emails_query = """
        SELECT 
            mail,
            name,
            COUNT(*) as login_count
        FROM `s360-demand-sensing.web_app_logs.web_app_logins`
        GROUP BY mail, name
        ORDER BY login_count DESC
        LIMIT 1000
        """
        
        # Define functions to execute each query and process its results
        def execute_login_data_query():
            query_job = bigquery_client.query(query)
            results = query_job.result()
            
            login_data = []
            for row in results:
                login_data.append({
                    "date": row.login_date.isoformat() if row.login_date else None,
                    "mail": row.mail,
                    "name": row.name,
                    "domain": row.domain,
                    "login_count": row.login_count
                })
            return login_data
        
        def execute_daily_query():
            daily_job = bigquery_client.query(daily_query)
            daily_results = daily_job.result()
            
            daily_logins = []
            for row in daily_results:
                daily_logins.append({
                    "date": row.login_date.isoformat() if row.login_date else None,
                    "unique_users": row.unique_users,
                    "total_logins": row.total_logins
                })
            return daily_logins
        
        def execute_domain_query():
            domain_job = bigquery_client.query(domain_query)
            domain_results = domain_job.result()
            
            domain_logins = []
            for row in domain_results:
                domain_logins.append({
                    "domain": row.domain,
                    "unique_users": row.unique_users,
                    "total_logins": row.total_logins
                })
            return domain_logins
        
        def execute_top_users_query():
            top_users_job = bigquery_client.query(top_users_query)
            top_users_results = top_users_job.result()
            
            top_users = []
            for row in top_users_results:
                top_users.append({
                    "mail": row.mail,
                    "name": row.name,
                    "login_count": row.login_count
                })
            return top_users
        
        def execute_all_domains_query():
            all_domains_job = bigquery_client.query(all_domains_query)
            all_domains_results = all_domains_job.result()
            
            all_domains = []
            for row in all_domains_results:
                all_domains.append({
                    "domain": row.domain,
                    "user_count": row.user_count
                })
            return all_domains
        
        def execute_all_emails_query():
            all_emails_job = bigquery_client.query(all_emails_query)
            all_emails_results = all_emails_job.result()
            
            all_emails = []
            for row in all_emails_results:
                all_emails.append({
                    "email": row.mail,
                    "name": row.name,
                    "login_count": row.login_count
                })
            return all_emails
        
        # Use ThreadPoolExecutor to run all queries concurrently
        with ThreadPoolExecutor(max_workers=6) as executor:
            login_data_future = executor.submit(execute_login_data_query)
            daily_future = executor.submit(execute_daily_query)
            domain_future = executor.submit(execute_domain_query)
            top_users_future = executor.submit(execute_top_users_query)
            all_domains_future = executor.submit(execute_all_domains_query)
            all_emails_future = executor.submit(execute_all_emails_query)
            
            # Wait for all queries to complete and get results
            login_data = login_data_future.result()
            daily_logins = daily_future.result()
            domain_logins = domain_future.result()
            top_users = top_users_future.result()
            all_domains = all_domains_future.result()
            all_emails = all_emails_future.result()
        
        return jsonify({
            "success": True,
            "login_data": login_data,
            "daily_logins": daily_logins,
            "domain_logins": domain_logins,
            "top_users": top_users,
            "all_domains": [d["domain"] for d in all_domains],
            "all_emails": [e["email"] for e in all_emails],
            "login_entries": login_data
        })
        
    except Exception as e:
        print(f"Error fetching login activity: {str(e)}")
        return jsonify({"error": f"Failed to fetch login activity: {str(e)}"}), 500

@app.route("/api/data/datapoints-count", methods=["GET"])
@token_required
def get_datapoints_count(current_user):
    """
    Get the count of historical datapoints from BestSellersProductClusterMonthly
    """
    try:
        # Query to count rows in the BestSellersProductClusterMonthly table
        query = """
            SELECT COUNT(*) as count 
            FROM `s360-demand-sensing.ds_master_raw_data.BestSellersProductClusterMonthly_11097323`
        """
        
        query_job = bigquery_client.query(query)
        results = query_job.result()
        
        # Get the count from the result
        row = list(results)[0]
        count = row.count
        
        return jsonify({
            "count": count
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/data/categories-count", methods=["GET"])
@token_required
def get_categories_count(current_user):
    """
    Get the count of categories from the google_taxonomy table
    """
    try:
        # Query to count unique categories in the taxonomy table
        query = """
            SELECT COUNT(*) as count
            FROM `s360-demand-sensing.ds_master_transformed_data.google_taxonomy`
        """
        
        query_job = bigquery_client.query(query)
        results = query_job.result()
        
        # Get the count from the result
        row = list(results)[0]
        count = row.count
        
        return jsonify({
            "count": count
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/data/current-countries", methods=["GET"])
@token_required
def get_current_countries(current_user):
    """
    Get the current countries from the latest bestseller_monthly data partition
    """
    try:
        # Query to get the current countries from the latest partition
        query = """
            DECLARE latest_partition DATE DEFAULT (
              SELECT PARSE_DATE('%Y%m%d', partition_id)
              FROM  `s360-demand-sensing.ds_master_transformed_data.INFORMATION_SCHEMA.PARTITIONS`
              WHERE table_name = 'bestseller_monthly'
              ORDER BY partition_id DESC
              LIMIT 1
            );

            SELECT DISTINCT
              country_code
            FROM   `s360-demand-sensing.ds_master_transformed_data.bestseller_monthly`
            WHERE  date_month = latest_partition;
        """
        
        query_job = bigquery_client.query(query)
        results = query_job.result()
        
        # Convert to list
        countries = [row.country_code for row in results]
        
        return jsonify({
            "countries": countries
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/data/available-categories", methods=["GET"])
@token_required
def get_available_categories(current_user):
    """Get all available categories from google_taxonomy table."""
    try:
        client = bigquery.Client()
        query = """
            SELECT category 
            FROM `s360-demand-sensing.ds_master_transformed_data.google_taxonomy` 
            ORDER BY category
        """
        query_job = client.query(query)
        results = query_job.result()
        
        categories = [row.category for row in results]
        
        return jsonify({"categories": categories})
    except Exception as e:
        logging.error(f"Error fetching available categories: {e}")
        return jsonify({"error": "Failed to fetch categories"}), 500


@app.route("/api/admin/category-assortment-analysis", methods=["GET"])
def analyze_category_assortment(current_user=""):
    """
    Admin endpoint to analyze all projects and merchant centers,
    finding the categories with the most products in assortment.
    This endpoint is secured with a scheduler token and is meant to be called only by Google Cloud Scheduler.
    """
    # Check for the scheduler token in the Authorization header
    #scheduler_token = os.environ.get("SCHEDULER_TOKEN")
    #if not scheduler_token:
    #    logging.error("SCHEDULER_TOKEN environment variable is not set")
    #    return jsonify({"error": "Server configuration error"}), 500
    #    
    #auth_header = request.headers.get("Authorization")
    #expected_auth = f"Bearer {scheduler_token}"
    #
    #if not auth_header or auth_header != expected_auth:
    #    logging.warning("Unauthorized attempt to access category assortment analysis")
    #    return jsonify({"error": "Unauthorized"}), 401
        
    try:
        # Get all client projects from Firestore
        projects_ref = firestore_client.collection('client_projects')
        projects = list(projects_ref.stream())
        
        results = []
        log_rows_to_insert = []  # For BigQuery logging
        analysis_timestamp = datetime.now()
        
        # Get the most recent date available for bestseller data
        master_project_id = "s360-demand-sensing"
        most_recent_date_query = f"""
        SELECT MAX(date_month) as latest_date
        FROM `{master_project_id}.ds_master_transformed_data.bestseller_monthly`
        """
        most_recent_job = bigquery_client.query(most_recent_date_query)
        most_recent_results = list(most_recent_job.result())
        
        # Default to most recent date
        most_recent_date = None
        if most_recent_results and hasattr(most_recent_results[0], 'latest_date'):
            most_recent_date = most_recent_results[0].latest_date.isoformat()
        
        # Create BigQuery dataset and table if they don't exist
        try:
            # First, make sure the dataset exists
            dataset_ref = bigquery_client.dataset("web_app_logs", project=master_project_id)
            try:
                bigquery_client.get_dataset(dataset_ref)
            except NotFound:
                # Create the dataset if it doesn't exist
                dataset = bigquery.Dataset(dataset_ref)
                dataset.location = "EU"  # Set your preferred location
                bigquery_client.create_dataset(dataset)
                
            # Check if table exists, create if it doesn't
            table_id = f"{master_project_id}.web_app_logs.category_assortment_analysis"
            table_ref = bigquery_client.dataset("web_app_logs").table("category_assortment_analysis")
            
            try:
                bigquery_client.get_table(table_ref)
            except NotFound:
                # Define updated schema with new fields
                schema = [
                    bigquery.SchemaField("timestamp", "TIMESTAMP", mode="REQUIRED"),
                    bigquery.SchemaField("merchant_center_date", "DATE", mode="REQUIRED"),
                    bigquery.SchemaField("project_id", "STRING", mode="REQUIRED"),
                    bigquery.SchemaField("project_name", "STRING", mode="REQUIRED"),
                    bigquery.SchemaField("cloud_project_id", "STRING", mode="REQUIRED"),
                    bigquery.SchemaField("merchant_center_id", "STRING", mode="REQUIRED"),
                    bigquery.SchemaField("country_code", "STRING", mode="REQUIRED"),
                    bigquery.SchemaField("category", "STRING", mode="NULLABLE"),
                    bigquery.SchemaField("is_top_category", "BOOLEAN", mode="NULLABLE"),
                    bigquery.SchemaField("products_in_assortment", "INTEGER", mode="NULLABLE"),
                    bigquery.SchemaField("products_in_stock", "INTEGER", mode="NULLABLE"),
                    bigquery.SchemaField("products_out_stock", "INTEGER", mode="NULLABLE"),
                    bigquery.SchemaField("total_products", "INTEGER", mode="NULLABLE"),
                    bigquery.SchemaField("share_percentage", "FLOAT", mode="NULLABLE"),
                    bigquery.SchemaField("bestseller_date", "DATE", mode="NULLABLE")
                ]
                
                table = bigquery.Table(table_ref, schema=schema)
                table.time_partitioning = bigquery.TimePartitioning(
                    type_=bigquery.TimePartitioningType.DAY,
                    field="merchant_center_date"
                )
                table = bigquery_client.create_table(table)
                print(f"Created table {table.project}.{table.dataset_id}.{table.table_id}")
                
        except Exception as table_error:
            print(f"Error creating/checking BigQuery table: {str(table_error)}")
            # Continue processing even if table creation fails
        
        for project_doc in projects:
            project_data = project_doc.to_dict()
            project_id = project_doc.id
            cloud_project_id = project_data.get('cloudProjectId')
            merchant_centers = project_data.get('merchantCenters', [])
            
            # Skip if no cloud project ID or merchant centers
            if not cloud_project_id or not merchant_centers:
                continue
                
            project_result = {
                "project_id": project_id,
                "project_name": project_data.get('name', 'Unknown'),
                "cloud_project_id": cloud_project_id,
                "merchant_centers": []
            }
            
            # Process each merchant center
            for merchant_center in merchant_centers:
                merchant_center_id = merchant_center.get('merchantCenterId')
                country_code = merchant_center.get('code')
                
                if not merchant_center_id or not country_code:
                    continue
                
                try:
                    # Use updated query to get categories with products in assortment
                    
                    # Add date filter matching what frontend uses - this is crucial for matching counts
                    date_filter = most_recent_date if most_recent_date else "CURRENT_DATE()"
                    
                    query = f"""
                    WITH products AS (
                      SELECT DISTINCT
                        offer_id,
                        product_id,
                        availability
                      FROM `{cloud_project_id}.ds_raw_data.Products_{merchant_center_id}`
                      WHERE _PARTITIONTIME = (
                              SELECT MAX(_PARTITIONTIME)
                              FROM `{cloud_project_id}.ds_raw_data.Products_{merchant_center_id}`
                            )
                        AND channel    = 'online'
                        AND feed_label = '{country_code}'
                    ),

                    bestseller_main AS (
                      SELECT
                        category,
                        entity_id
                      FROM `s360-demand-sensing.ds_master_transformed_data.bestseller_monthly`
                      WHERE country_code = '{country_code}'
                        AND date_month   = '{date_filter}'
                    ),

                    total_bestseller_counts AS (
                      SELECT
                        category,
                        COUNT(entity_id) AS total_products
                      FROM bestseller_main
                      WHERE category IS NOT NULL
                      GROUP BY category
                    ),

                    mapping AS (
                      SELECT DISTINCT
                        m.entity_id,
                        m.product_id,
                        bm.category
                      FROM `{cloud_project_id}.ds_raw_data.BestSellersEntityProductMapping_{merchant_center_id}` AS m
                      LEFT JOIN bestseller_main AS bm
                        ON bm.entity_id = m.entity_id
                    ),

                    final AS (
                      SELECT
                        m.entity_id,
                        m.category,
                        p.availability
                      FROM products AS p
                      LEFT JOIN mapping AS m
                        ON p.product_id = m.product_id
                      WHERE m.category IS NOT NULL            -- drop unmatched rows
                    ),

                    entity_status AS (
                      SELECT
                        category,
                        entity_id,
                        LOGICAL_OR(availability = 'in stock')     AS has_in_stock,
                        LOGICAL_OR(availability = 'out of stock') AS any_out_stock
                      FROM final
                      GROUP BY category, entity_id
                    ),

                    category_counts AS (
                      SELECT
                        e.category                         AS level_1,
                        COUNT(*)                           AS products_in_assortment,
                        COUNTIF(has_in_stock)              AS products_in_stock,
                        COUNTIF(NOT has_in_stock
                                AND any_out_stock)         AS products_out_stock,
                        t.total_products,
                        SAFE_DIVIDE(COUNT(*), t.total_products) AS share_of_total
                      FROM entity_status e
                      JOIN total_bestseller_counts t
                        ON e.category = t.category
                      GROUP BY e.category, t.total_products
                      ORDER BY products_in_assortment DESC
                    )

                    SELECT *
                    FROM category_counts
                    """
                    
                    # Execute the query
                    query_job = bigquery_client.query(query)
                    results_rows = list(query_job.result())
                    
                    # If there are categories with products in assortment
                    if results_rows:
                        # Find top category for summary
                        top_category = results_rows[0].level_1
                        top_products_in_assortment = results_rows[0].products_in_assortment
                        top_products_in_stock = results_rows[0].products_in_stock
                        top_products_out_stock = results_rows[0].products_out_stock
                        top_total_products = results_rows[0].total_products
                        top_share_percentage = round(results_rows[0].share_of_total * 100, 2) if results_rows[0].share_of_total else 0
                        
                        # Add merchant center summary to result (using top category for summary)
                        merchant_result = {
                            "merchant_center_id": merchant_center_id,
                            "country_code": country_code,
                            "top_category": top_category,
                            "products_in_assortment": top_products_in_assortment,
                            "products_in_stock": top_products_in_stock,
                            "products_out_stock": top_products_out_stock,
                            "total_products": top_total_products,
                            "share_of_total": top_share_percentage,
                            "date_used": most_recent_date,
                            "categories_count": len(results_rows)
                        }
                        
                        # Process all categories
                        for row in results_rows:
                            category = row.level_1
                            products_in_assortment = row.products_in_assortment
                            products_in_stock = row.products_in_stock
                            products_out_stock = row.products_out_stock
                            total_products = row.total_products
                            share_of_total = row.share_of_total
                            share_percentage = round(share_of_total * 100, 2) if share_of_total else 0
                            
                            # Prepare data for BigQuery insert for this category
                            bq_row = {
                                "timestamp": analysis_timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                                "merchant_center_date": analysis_timestamp.strftime('%Y-%m-%d'),
                                "project_id": project_id,
                                "project_name": project_data.get('name', 'Unknown'),
                                "cloud_project_id": cloud_project_id,
                                "merchant_center_id": merchant_center_id,
                                "country_code": country_code,
                                "category": category,
                                "is_top_category": (category == top_category),
                                "products_in_assortment": products_in_assortment,
                                "products_in_stock": products_in_stock,
                                "products_out_stock": products_out_stock,
                                "total_products": total_products,
                                "share_percentage": share_percentage,
                                "bestseller_date": most_recent_date
                            }
                            log_rows_to_insert.append(bq_row)
                    else:
                        # No categories with products in assortment
                        merchant_result = {
                            "merchant_center_id": merchant_center_id,
                            "country_code": country_code,
                            "top_category": None,
                            "products_in_assortment": 0,
                            "products_in_stock": 0,
                            "products_out_stock": 0,
                            "total_products": 0,
                            "share_of_total": 0,
                            "date_used": most_recent_date,
                            "categories_count": 0
                        }
                    
                    project_result["merchant_centers"].append(merchant_result)
                    
                except Exception as mc_error:
                    # Log error but continue with next merchant center
                    print(f"Error processing merchant center {merchant_center_id}: {str(mc_error)}")
                    merchant_result = {
                        "merchant_center_id": merchant_center_id,
                        "country_code": country_code,
                        "error": str(mc_error)
                    }
                    project_result["merchant_centers"].append(merchant_result)
            
            # Only add project to results if at least one merchant center was processed
            if project_result["merchant_centers"]:
                results.append(project_result)
        
        # Insert data into BigQuery
        if log_rows_to_insert:
            try:
                table_id = f"{master_project_id}.web_app_logs.category_assortment_analysis"
                errors = bigquery_client.insert_rows_json(table_id, log_rows_to_insert)
                if errors:
                    print(f"Encountered errors while inserting rows: {errors}")
                else:
                    print(f"Successfully inserted {len(log_rows_to_insert)} rows into {table_id}")
            except Exception as insert_error:
                print(f"Error inserting data into BigQuery: {str(insert_error)}")
        
        # Return the analysis results
        return jsonify({
            "success": True,
            "timestamp": analysis_timestamp.isoformat(),
            "date_used_for_filtering": most_recent_date,
            "results": results,
            "logged_categories_count": len(log_rows_to_insert),
            "logged_to_bigquery": len(log_rows_to_insert) > 0
        })
        
    except Exception as e:
        print(f"Error analyzing category assortment: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Failed to analyze category assortment: {str(e)}"
        }), 500




    
@app.route("/api/data/category-trend", methods=["GET"])
@token_required
def get_category_trend(current_user):
    try:
        
        # Define the query to get top categories trend
        query = """
        SELECT 
            bestseller_date,
            AVG(share_percentage) as avg_share_percentage
        FROM `s360-demand-sensing.web_app_logs.category_assortment_analysis`
        WHERE is_top_category = true
        GROUP BY 1
        ORDER BY 1
        """
        
        # Run the query
        query_job = bigquery_client.query(query)
        results = query_job.result()
        
        # Convert results to a list of dictionaries
        trend_data = []
        for row in results:
            trend_data.append({
                "date": row.bestseller_date.strftime('%Y-%m-%d') if row.bestseller_date else None,
                "avgSharePercentage": row.avg_share_percentage
            })
        
        return jsonify({
            "success": True,
            "data": trend_data
        })
    
    except Exception as e:
        print(f"Error fetching category trend data: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Failed to fetch category trend data"
        }), 500

@app.route("/api/performance/category-demand", methods=["GET"])
@token_required
@project_access_required
def get_category_demand_data(current_user, cloud_project_id=None):
    """
    Get category demand data over time for the area chart in the Performance dashboard.
    Required query parameters:
    - country: The country code to filter by
    - project_id: The Firestore project ID to filter by
    Optional query parameters:
    - categories: Comma-separated list of categories to filter by
    """
    try:
        # Get parameters from request
        country = request.args.get("country")
        categories_param = request.args.get("categories")
        
        # Validate country parameter
        if not country:
            return jsonify({"error": "Country parameter is required"}), 400
            
        # Get project ID - use the one from the decorator or from query param
        project_id = request.args.get("project_id", cloud_project_id)
        if not project_id:
            return jsonify({"error": "Project ID is required"}), 400
            
        # Parse categories if provided
        categories = []
        if categories_param:
            categories = categories_param.split(",")
            
        # Create BigQuery client
        client = bigquery.Client()
        
        # Build the query to get time series data
        query = f"""
        WITH category_data AS (
            SELECT 
                bestseller_date,
                category,
                AVG(share_percentage) as share_percentage
            FROM `s360-demand-sensing.web_app_logs.category_assortment_analysis`
            WHERE project_id = '{project_id}'
            AND country_code = '{country}'
        """
        
        # Add category filter if provided
        if categories and len(categories) > 0:
            category_conditions = ", ".join([f"'{cat.strip()}'" for cat in categories])
            query += f"AND category IN ({category_conditions})"
            
        # Complete the query
        query += """
            GROUP BY bestseller_date, category
        )
        SELECT 
            bestseller_date,
            category,
            share_percentage
        FROM category_data
        ORDER BY bestseller_date, share_percentage DESC
        """
        
        # Run the query
        query_job = client.query(query)
        results = query_job.result()
        
        # Process the results into a format suitable for a time series chart
        # We need a format like: [{date: "2023-01-01", category1: value1, category2: value2, ...}]
        time_series_data = {}
        categories_set = set()
        
        for row in results:
            date_str = row.bestseller_date.strftime("%Y-%m-%d")
            category = row.category
            value = row.share_percentage
            
            if date_str not in time_series_data:
                time_series_data[date_str] = {}
                
            time_series_data[date_str][category] = value
            categories_set.add(category)
        
        # Convert to list format for frontend
        chart_data = []
        categories_list = list(categories_set)
        
        for date_str in sorted(time_series_data.keys()):
            data_point = {"date": date_str}
            
            for category in categories_list:
                data_point[category] = time_series_data[date_str].get(category, 0)
                
            chart_data.append(data_point)
            
        # Return the data
        return jsonify({
            "success": True,
            "data": chart_data,
            "categories": categories_list,
            "project_id": project_id,
            "country": country
        })
        
    except Exception as e:
        print(f"Error fetching category demand data: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Failed to fetch category demand data: {str(e)}"
        }), 500

@app.route("/api/performance/market-share", methods=["GET"])
@token_required
@project_access_required
def get_market_share_data(current_user, cloud_project_id=None):
    """
    Get market share data for the Performance dashboard.
    Required query parameters:
    - country: The country code to filter by
    Optional query parameters:
    - categories: Comma-separated list of categories to filter by 
      (if not provided, all categories will be included)
    """
    try:
        # Get parameters from request
        country = request.args.get("country")
        categories_param = request.args.get("categories")
        
        # Validate country parameter
        if not country:
            return jsonify({"error": "Country parameter is required"}), 400
            
        # Get project ID - use the one from the decorator or from query param
        project_id = request.args.get("project_id", cloud_project_id)
        if not project_id:
            return jsonify({"error": "Project ID is required"}), 400
            
        # Parse categories if provided
        categories = []
        if categories_param:
            categories = categories_param.split(",")
            
        # Create BigQuery client
        client = bigquery.Client()
        
        # First, find the latest available date for this project/country
        date_query = f"""
        SELECT MAX(bestseller_date) as latest_date
        FROM `s360-demand-sensing.web_app_logs.category_assortment_analysis`
        WHERE project_id = '{project_id}'
        AND country_code = '{country}'
        """
        
        latest_date_results = client.query(date_query).result()
        latest_date = None
        
        for row in latest_date_results:
            latest_date = row.latest_date
            break
            
        if not latest_date:
            return jsonify({
                "market_share": None,
                "error": "No data available for this project/country"
            }), 200
            
        # Format date as string for the query
        latest_date_str = latest_date.strftime("%Y-%m-%d")
            
        # Build the main query
        base_query = f"""
        SELECT AVG(share_percentage) as avg_share
        FROM `s360-demand-sensing.web_app_logs.category_assortment_analysis`
        WHERE project_id = '{project_id}'
        AND country_code = '{country}'
        AND bestseller_date = '{latest_date_str}'
        """
        
        # Add category filter if provided
        if categories and len(categories) > 0:
            category_conditions = ", ".join([f"'{cat.strip()}'" for cat in categories])
            base_query += f"AND category IN ({category_conditions})"
            
        # Run the query
        query_job = client.query(base_query)
        results = query_job.result()
        
        avg_share = None
        for row in results:
            avg_share = row.avg_share
            break

        # Return the results
        return jsonify({
            "market_share": avg_share,
            "latest_date": latest_date_str,
            "project_id": project_id,
            "country": country,
            "categories": categories
        }), 200
        
    except Exception as e:
        app.logger.error(f"Error getting market share data: {str(e)}")
        return jsonify({"error": f"Failed to get market share data: {str(e)}"}), 500

@app.route("/api/assortment/category-products", methods=["GET"])
@token_required
@project_access_required
def get_category_products_in_assortment(current_user, cloud_project_id=None):
    try:
        # Get country from query params
        country = request.args.get("country")
        if not country:
            return jsonify({"error": "Country parameter is required"}), 400
            
        # Get project ID - use the one from the decorator or from query param
        project_id = request.args.get("project_id", cloud_project_id)
        if not project_id:
            return jsonify({"error": "Project ID is required"}), 400
            
        # Create BigQuery client
        client = bigquery.Client()
        
        # Query to get products in assortment per category across all dates
        query = f"""
        SELECT 
            category,
            MIN(bestseller_date) as start_date,
            MAX(bestseller_date) as end_date,
            AVG(products_in_stock) as avg_products_in_stock
        FROM `s360-demand-sensing.web_app_logs.category_assortment_analysis`
        WHERE project_id = '{project_id}'
        AND country_code = '{country}'
        GROUP BY category
        ORDER BY avg_products_in_stock DESC
        """
        
        query_job = client.query(query)
        results = query_job.result()
        
        # Process results
        categories = []
        products = []
        date_range = {"start": None, "end": None}
        
        for row in results:
            categories.append(row.category)
            products.append(row.avg_products_in_stock)
            
            # Update date range
            if date_range["start"] is None or row.start_date < date_range["start"]:
                date_range["start"] = row.start_date
            if date_range["end"] is None or row.end_date > date_range["end"]:
                date_range["end"] = row.end_date
        
        # Format dates as strings
        if date_range["start"] and date_range["end"]:
            date_range["start"] = date_range["start"].strftime("%Y-%m-%d")
            date_range["end"] = date_range["end"].strftime("%Y-%m-%d")
        
        return jsonify({
            "categories": categories,
            "products": products,
            "dateRange": date_range
        }), 200
    
    except Exception as e:
        logging.error(f"Error in get_category_products_in_assortment: {str(e)}")
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

@app.route("/api/admin/project-billing", methods=["GET"])
@token_required_admin
def get_project_billing(current_user):
    """
    Get billing information for all projects with cost allocation from shared project.
    Optional query parameters:
    - start_date: Start date for billing period (YYYY-MM-DD)
    - end_date: End date for billing period (YYYY-MM-DD)
    - period: Predefined period (last30days, last90days, lastMonth, thisMonth)
    """
    try:
        # Get date parameters
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        period = request.args.get('period', 'thisMonth')
        
        # Set default date range based on period if dates are not provided
        today = datetime.now()
        if not start_date or not end_date:
            if period == 'last30days':
                start_date = (today - timedelta(days=30)).strftime('%Y-%m-%d')
                end_date = today.strftime('%Y-%m-%d')
            elif period == 'last90days':
                start_date = (today - timedelta(days=90)).strftime('%Y-%m-%d')
                end_date = today.strftime('%Y-%m-%d')
            elif period == 'lastMonth':
                # Last complete month
                last_month = today.replace(day=1) - timedelta(days=1)
                start_date = last_month.replace(day=1).strftime('%Y-%m-%d')
                end_date = last_month.strftime('%Y-%m-%d')
            else:  # thisMonth (default)
                # Current month to date
                start_date = today.replace(day=1).strftime('%Y-%m-%d')
                end_date = today.strftime('%Y-%m-%d')
        
        # We need to query two different datasets in different regions
        # Query 1: Client project costs and original shared project cost (EU region)
        eu_time_series_query = f"""
        WITH daily_costs AS (
            SELECT
                DATE(_PARTITIONTIME) AS usage_date,
                project.id AS project_id,
                project.name AS project_name,
                SUM(cost) + SUM(IFNULL((SELECT SUM(c.amount) FROM UNNEST(credits) c), 0)) AS net_cost
            FROM `s360-cloud-billing.s360_tech_solutions_incl_looker.gcp_billing_export_v1_01AAA1_F0A050_07E519`
            WHERE DATE(_PARTITIONTIME) BETWEEN DATE('{start_date}') AND DATE('{end_date}')
            AND (LOWER(project.id) LIKE '%demand%' OR LOWER(project.id) LIKE '%sense%')
            AND project.id != 's360-demand-sense'
            GROUP BY usage_date, project_id, project_name
            ORDER BY usage_date ASC
        )
        
        SELECT
            usage_date,
            project_id,
            project_name,
            net_cost
        FROM daily_costs
        """
        
        # Query 2: Additional shared project costs from US region
        us_time_series_query = f"""
        SELECT
            DATE(_PARTITIONTIME) AS usage_date,
            project.id AS project_id,
            project.name AS project_name,
            SUM(cost) + SUM(IFNULL((SELECT SUM(c.amount) FROM UNNEST(credits) c), 0)) AS net_cost
        FROM `retail-solution-master.gcp_billing_export.gcp_billing_export_v1_*`
        WHERE DATE(_PARTITIONTIME) BETWEEN DATE('{start_date}') AND DATE('{end_date}')
        AND project.id = 's360-demand-sensing'
        GROUP BY usage_date, project_id, project_name
        ORDER BY usage_date ASC
        """
        
        # EU query for project costs and service breakdown
        eu_project_query = f"""
        WITH project_costs AS (
            SELECT
                project.id AS project_id,
                project.name AS project_name,
                service.description AS service_description,
                SUM(cost) AS total_cost,
                SUM(IFNULL((SELECT SUM(c.amount) FROM UNNEST(credits) c), 0)) AS total_credits,
                SUM(cost) + SUM(IFNULL((SELECT SUM(c.amount) FROM UNNEST(credits) c), 0)) AS net_cost
            FROM `s360-cloud-billing.s360_tech_solutions_incl_looker.gcp_billing_export_v1_01AAA1_F0A050_07E519`
            WHERE DATE(_PARTITIONTIME) BETWEEN DATE('{start_date}') AND DATE('{end_date}')
            AND (LOWER(project.id) LIKE '%demand%' OR LOWER(project.id) LIKE '%sense%')
            AND project.id != 's360-demand-sense'
            GROUP BY project_id, project_name, service_description
        )
        
        SELECT
            project_id,
            project_name,
            service_description,
            net_cost
        FROM project_costs
        """
        
        # US query for additional shared project costs
        us_project_query = f"""
        SELECT
            project.id AS project_id,
            project.name AS project_name,
            service.description AS service_description,
            SUM(cost) + SUM(IFNULL((SELECT SUM(c.amount) FROM UNNEST(credits) c), 0)) AS net_cost
        FROM `retail-solution-master.gcp_billing_export.gcp_billing_export_v1_*`
        WHERE DATE(_PARTITIONTIME) BETWEEN DATE('{start_date}') AND DATE('{end_date}')
        AND project.id = 's360-demand-sensing'
        GROUP BY project_id, project_name, service_description
        """

        # Function to fetch Firestore project info
        def fetch_firestore_project_info():
            projects_ref = firestore_client.collection('client_projects')
            projects_docs = list(projects_ref.stream())
            
            # Create a mapping of cloud project IDs to Firestore document IDs and status
            project_info = {}
            for doc in projects_docs:
                project_data = doc.to_dict()
                if 'cloudProjectId' in project_data:
                    project_info[project_data['cloudProjectId']] = {
                        'id': doc.id,
                        'status': project_data.get('status', 'active'),
                        'name': project_data.get('name', 'Unknown'),
                        'merchantCenters': project_data.get('merchantCenters', [])
                    }
            return project_info

        # Function to process time series data to get daily costs by project
        def process_daily_costs(combined_ts_results):
            daily_costs_by_project = {}
            
            for row in combined_ts_results:
                date_str = row.usage_date.strftime('%Y-%m-%d')
                project_id = row.project_id
                
                if date_str not in daily_costs_by_project:
                    daily_costs_by_project[date_str] = {}
                    
                # Add or update project cost for this date
                if project_id in daily_costs_by_project[date_str]:
                    daily_costs_by_project[date_str][project_id]['net_cost'] += row.net_cost
                else:
                    daily_costs_by_project[date_str][project_id] = {
                        'project_name': row.project_name,
                        'net_cost': row.net_cost
                    }
            return daily_costs_by_project

        # Function to process project costs
        def process_project_costs(combined_proj_results):
            project_costs = {}
            shared_project_cost = 0
            
            for row in combined_proj_results:
                project_id = row.project_id
                
                if project_id not in project_costs:
                    project_costs[project_id] = {
                        'project_name': row.project_name,
                        'net_cost': 0,
                        'services': {}
                    }
                    
                # Add to total project cost
                project_costs[project_id]['net_cost'] += row.net_cost
                
                # Add to service breakdown
                service_desc = row.service_description
                if service_desc not in project_costs[project_id]['services']:
                    project_costs[project_id]['services'][service_desc] = 0
                    
                project_costs[project_id]['services'][service_desc] += row.net_cost
                
                # Track shared project cost separately
                if project_id == 's360-demand-sensing':
                    shared_project_cost += row.net_cost
            
            total_client_cost = sum([
                data['net_cost'] for pid, data in project_costs.items() 
                if pid != 's360-demand-sensing' and pid != 's360-demand-sense'
            ])
            
            return project_costs, shared_project_cost, total_client_cost

        # Function to process time series data
        def process_time_series(daily_costs_by_project):
            time_series_data = {}
            overall_time_series = []
            
            for date_str, projects in daily_costs_by_project.items():
                # Calculate shared cost for this day
                daily_shared_cost = projects.get('s360-demand-sensing', {}).get('net_cost', 0)
                
                # Calculate total client cost for this day (excluding shared project)
                daily_total_client_cost = sum([
                    data['net_cost'] for pid, data in projects.items()
                    if pid != 's360-demand-sensing' and pid != 's360-demand-sense'
                ])
                
                # Initialize daily total for overall series
                daily_overall = {
                    'date': date_str,
                    'direct_cost': 0,
                    'allocated_cost': 0,
                    'total_cost': 0
                }
                
                # Process each client project
                for project_id, data in projects.items():
                    if project_id != 's360-demand-sensing' and project_id != 's360-demand-sense':
                        direct_cost = data['net_cost']
                        
                        # Calculate allocated cost (shared cost * project's proportion of total client cost)
                        allocated_cost = 0
                        if daily_total_client_cost > 0 and daily_shared_cost > 0:
                            allocated_cost = (direct_cost / daily_total_client_cost) * daily_shared_cost
                        
                        total_cost = direct_cost + allocated_cost
                        
                        # Add to project's time series
                        if project_id not in time_series_data:
                            time_series_data[project_id] = {
                                'project_name': data['project_name'],
                                'dates': [],
                                'direct_costs': [],
                                'allocated_costs': [],
                                'total_costs': []
                            }
                        
                        time_series_data[project_id]['dates'].append(date_str)
                        time_series_data[project_id]['direct_costs'].append(direct_cost)
                        time_series_data[project_id]['allocated_costs'].append(allocated_cost)
                        time_series_data[project_id]['total_costs'].append(total_cost)
                        
                        # Add to overall daily totals
                        daily_overall['direct_cost'] += direct_cost
                        daily_overall['allocated_cost'] += allocated_cost
                        daily_overall['total_cost'] += total_cost
                
                # Add to overall time series if we have client projects for this day
                if daily_overall['direct_cost'] > 0:
                    overall_time_series.append(daily_overall)
                    
            # Sort the overall time series by date
            overall_time_series.sort(key=lambda x: x['date'])
            return time_series_data, overall_time_series

        # Function to prepare final billing data
        def prepare_billing_data(project_costs, total_client_cost, shared_project_cost, time_series_data, project_info):
            billing_data = []
            
            # Process each client project
            for project_id, data in project_costs.items():
                if project_id != 's360-demand-sensing' and project_id != 's360-demand-sense':
                    direct_cost = data['net_cost']
                    
                    # Calculate allocated cost (shared cost * project's proportion of total client cost)
                    allocated_cost = 0
                    if total_client_cost > 0 and shared_project_cost > 0:
                        allocated_cost = (direct_cost / total_client_cost) * shared_project_cost
                    
                    total_cost = direct_cost + allocated_cost
                    
                    # Calculate service percentages
                    services_data = []
                    for service, cost in data['services'].items():
                        percentage = 0
                        if direct_cost > 0:
                            percentage = round((cost / direct_cost) * 100, 2)
                        
                        services_data.append({
                            'name': service,
                            'cost': cost,
                            'percentage': percentage
                        })
                    
                    # Sort services by cost
                    services_data.sort(key=lambda x: x['cost'], reverse=True)
                    
                    # Create project billing data
                    project_data = {
                        'project_id': project_id,
                        'project_name': data['project_name'],
                        'direct_cost': direct_cost,
                        'allocated_shared_cost': allocated_cost,
                        'total_cost': total_cost,
                        'services': services_data,
                        'firestore_id': project_info.get(project_id, {}).get('id'),
                        'status': project_info.get(project_id, {}).get('status'),
                        'merchant_centers': project_info.get(project_id, {}).get('merchantCenters', []),
                        # Add time series data if available
                        'time_series': time_series_data.get(project_id, {
                            'dates': [],
                            'direct_costs': [],
                            'allocated_costs': [],
                            'total_costs': []
                        })
                    }
                    billing_data.append(project_data)
            
            # Sort billing data by total cost
            billing_data.sort(key=lambda x: x['total_cost'], reverse=True)
            
            # Calculate summary statistics
            total_direct_cost = sum(project['direct_cost'] for project in billing_data) if billing_data else 0
            total_allocated_cost = sum(project['allocated_shared_cost'] for project in billing_data) if billing_data else 0
            total_cost = sum(project['total_cost'] for project in billing_data) if billing_data else 0
            
            # If no results, add Firestore projects with zero costs
            if not billing_data:
                for project_id, info in project_info.items():
                    if project_id != 's360-demand-sensing' and project_id != 's360-demand-sense':
                        billing_data.append({
                            'project_id': project_id,
                            'project_name': info.get('name', project_id),
                            'direct_cost': 0,
                            'allocated_shared_cost': 0,
                            'total_cost': 0,
                            'services': [],
                            'firestore_id': info.get('id'),
                            'status': info.get('status', 'active'),
                            'merchant_centers': info.get('merchantCenters', []),
                            'time_series': {
                                'dates': [],
                                'direct_costs': [],
                                'allocated_costs': [],
                                'total_costs': []
                            }
                        })
            
            return billing_data, total_direct_cost, total_allocated_cost, total_cost
        
        # Execute all tasks concurrently with an increased number of workers
        with ThreadPoolExecutor(max_workers=8) as executor:
            # Execute BigQuery queries
            eu_ts_future = executor.submit(bigquery_client.query, eu_time_series_query)
            us_ts_future = executor.submit(bigquery_client.query, us_time_series_query)
            eu_proj_future = executor.submit(bigquery_client.query, eu_project_query)
            us_proj_future = executor.submit(bigquery_client.query, us_project_query)
            
            # Execute Firestore fetch in parallel
            firestore_future = executor.submit(fetch_firestore_project_info)
            
            # Get results from all queries
            eu_ts_results = list(eu_ts_future.result())
            us_ts_results = list(us_ts_future.result())
            eu_proj_results = list(eu_proj_future.result())
            us_proj_results = list(us_proj_future.result())
            
            # Combine time series results from both sources
            combined_ts_results = eu_ts_results + us_ts_results
            
            # Combine project costs results
            combined_proj_results = eu_proj_results + us_proj_results
            
            # Process data in parallel
            daily_costs_future = executor.submit(process_daily_costs, combined_ts_results)
            project_costs_future = executor.submit(process_project_costs, combined_proj_results)
            
            # Wait for intermediate results
            daily_costs_by_project = daily_costs_future.result()
            project_costs, shared_project_cost, total_client_cost = project_costs_future.result()
            project_info = firestore_future.result()
            
            # Process time series data
            time_series_future = executor.submit(process_time_series, daily_costs_by_project)
            
            # Wait for time series results
            time_series_data, overall_time_series = time_series_future.result()
            
            # Prepare final billing data
            billing_data_future = executor.submit(
                prepare_billing_data, 
                project_costs, 
                total_client_cost, 
                shared_project_cost, 
                time_series_data, 
                project_info
            )
            
            # Get final results
            billing_data, total_direct_cost, total_allocated_cost, total_cost = billing_data_future.result()
        
        return jsonify({
            'success': True,
            'billing_data': billing_data,
            'summary': {
                'total_direct_cost': total_direct_cost,
                'total_allocated_cost': total_allocated_cost,
                'total_cost': total_cost,
                'date_range': {
                    'start_date': start_date,
                    'end_date': end_date,
                    'period': period
                },
                'time_series': overall_time_series
            }
        })
        
    except Exception as e:
        print(f"Error retrieving billing data: {str(e)}")
        return jsonify({'success': False, 'error': f"Failed to retrieve billing data: {str(e)}"}), 500

@app.route("/api/brand-trends", methods=["GET"])
@token_required
@project_access_required
def get_brand_trends(current_user, cloud_project_id=None):

    try:
        # Get query parameters
        inspiration_market = request.args.get('inspiration_market')
        date_month = request.args.get('date_month')
        sort_column = request.args.get('sort_column', 'highest_ranking')
        sort_direction = request.args.get('sort_direction', 'asc').upper()
        categories = request.args.getlist('categories[]')
        project_markets = request.args.getlist('project_markets[]')
        brand_filter = request.args.get('brand_filter', '')
        
        # Pagination parameters
        limit = request.args.get('limit', 100, type=int)
        offset = request.args.get('offset', 0, type=int)
        
        # Validate required parameters
        if not inspiration_market or not date_month:
            return jsonify({
                "success": False,
                "error": "Missing required parameters: inspiration_market and date_month"
            }), 400
        
        # Calculate previous month's date
        try:
            current_date = datetime.strptime(date_month, '%Y-%m-%d')
            
            # Get the first day of current month
            first_day = current_date.replace(day=1)
            
            # Subtract one day to get the last day of previous month
            last_day_prev_month = first_day - timedelta(days=1)
            
            # Get the first day of previous month
            prev_month = last_day_prev_month.replace(day=1).strftime('%Y-%m-%d')
        except Exception as e:
            print(f"Error calculating previous month: {str(e)}")
            prev_month = None
        
        # Build category filter clause if provided
        category_filter = ""
        if categories and len(categories) > 0:
            # Fix the syntax error by defining the escape outside the f-string
            category_strings = []
            for cat in categories:
                # Replace single quotes with two single quotes for SQL
                escaped_cat = cat.replace("'", "''")
                category_strings.append(f"'{escaped_cat}'")
            
            category_filter = f"AND category IN ({', '.join(category_strings)})"
        
        # Build brand filter clause if provided
        brand_filter_clause = ""
        if brand_filter:
            # Escape single quotes for SQL
            escaped_brand = brand_filter.replace("'", "''")
            brand_filter_clause = f"AND LOWER(brand) LIKE LOWER('%{escaped_brand}%')"
        
        # Build the query to get brand trends data for inspiration market
        query = f"""
        WITH ranked_products AS (
          SELECT
            brand,
            entity_id,
            title,
            rank,
            ROW_NUMBER() OVER (PARTITION BY brand ORDER BY rank ASC) as rank_within_brand
          FROM `s360-demand-sensing.ds_master_transformed_data.bestseller_monthly`
          WHERE country_code = '{inspiration_market}'
          AND date_month = '{date_month}'
          {category_filter}
          {brand_filter_clause}
        )
        
        SELECT
          brand,
          (SELECT title FROM ranked_products rp WHERE rp.brand = r.brand AND rank_within_brand = 1) as highest_ranking_product,
          MIN(rank) as highest_ranking,
          COUNT(DISTINCT entity_id) as total_products
        FROM ranked_products r
        WHERE brand IS NOT NULL
        GROUP BY brand
        ORDER BY {sort_column} {sort_direction}
        LIMIT {limit} OFFSET {offset}
        """
        
        # Count query for total records (for pagination)
        count_query = f"""
        WITH ranked_products AS (
          SELECT
            brand,
            entity_id
          FROM `s360-demand-sensing.ds_master_transformed_data.bestseller_monthly`
          WHERE country_code = '{inspiration_market}'
          AND date_month = '{date_month}'
          {category_filter}
          {brand_filter_clause}
        )
        
        SELECT
          COUNT(DISTINCT brand) as total_count
        FROM ranked_products
        WHERE brand IS NOT NULL
        """

        # Execute both queries concurrently
        with ThreadPoolExecutor(max_workers=2) as executor:
            query_future = executor.submit(bigquery_client.query, query)
            count_future = executor.submit(bigquery_client.query, count_query)
            # Get results
            query_job = query_future.result()
            count_job = count_future.result()

        # Process the results
        trends = []
        for row in query_job.result():
            trend = {
                "brand": row.brand,
                "highest_ranking_product": row.highest_ranking_product,
                "highest_ranking": row.highest_ranking,
                "total_products": row.total_products,
                "project_market_data": {}  # Will store data from project markets
            }
            trends.append(trend)
        
        # Get total count from count query
        total_count = 0
        for row in count_job.result():
            total_count = row.total_count
            break
        
        # If project markets are specified, get data for each market
        if project_markets and len(project_markets) > 0:
            # Get brand data dictionary for faster lookups
            brand_data = {trend["brand"]: trend for trend in trends}
            
            # Query each project market
            for market in project_markets:
                project_market_query = f"""
                WITH ranked_products AS (
                  SELECT
                    brand,
                    entity_id,
                    title,
                    rank,
                    ROW_NUMBER() OVER (PARTITION BY brand ORDER BY rank ASC) as rank_within_brand
                  FROM `s360-demand-sensing.ds_master_transformed_data.bestseller_monthly`
                  WHERE country_code = '{market}'
                  AND date_month = '{date_month}'
                  {category_filter}
                )
                
                SELECT
                  brand,
                  MIN(rank) as highest_ranking,
                  COUNT(DISTINCT entity_id) as total_products
                FROM ranked_products r
                WHERE brand IS NOT NULL
                GROUP BY brand
                """

                project_market_job = bigquery_client.query(project_market_query)
                project_market_results = project_market_job.result()
                
                # Add project market data to the corresponding brands
                for row in project_market_results:
                    if row.brand in brand_data:
                        brand_data[row.brand]["project_market_data"][market] = {
                            "highest_ranking": row.highest_ranking,
                            "total_products": row.total_products
                        }
        
        # Add previous month data if available
        if prev_month:
            prev_month_query = f"""
            WITH ranked_products AS (
              SELECT
                brand,
                entity_id,
                rank,
                ROW_NUMBER() OVER (PARTITION BY brand ORDER BY rank ASC) as rank_within_brand
              FROM `s360-demand-sensing.ds_master_transformed_data.bestseller_monthly`
              WHERE country_code = '{inspiration_market}'
              AND date_month = '{prev_month}'
              {category_filter}
            )
            
            SELECT
              brand,
              MIN(rank) as highest_ranking,
              COUNT(DISTINCT entity_id) as total_products
            FROM ranked_products r
            WHERE brand IS NOT NULL
            GROUP BY brand
            """
            
            prev_month_job = bigquery_client.query(prev_month_query)
            prev_month_results = prev_month_job.result()
            
            # Create lookup dictionary for previous month data
            prev_month_data = {}
            for row in prev_month_results:
                prev_month_data[row.brand] = {
                    "highest_ranking": row.highest_ranking,
                    "total_products": row.total_products
                }
            
            # Calculate month over month changes
            for trend in trends:
                if trend["brand"] in prev_month_data:
                    prev_data = prev_month_data[trend["brand"]]
                    
                    # Calculate ranking change (negative is improvement, positive is decline)
                    rank_change = trend["highest_ranking"] - prev_data["highest_ranking"]
                    trend["highest_ranking_change"] = rank_change
                    
                    # Calculate total products change
                    products_change = trend["total_products"] - prev_data["total_products"]
                    trend["total_products_change"] = products_change
                    trend["total_products_change_pct"] = (products_change / prev_data["total_products"]) * 100 if prev_data["total_products"] > 0 else 0
                else:
                    # No previous month data available
                    trend["highest_ranking_change"] = None
                    trend["total_products_change"] = None
                    trend["total_products_change_pct"] = None



        return jsonify({
            "success": True,
            "trends": trends,
            "count": len(trends),
            "total": total_count,
            "page": offset // limit + 1,
            "pages": (total_count + limit - 1) // limit,
            "filters": {
                "inspiration_market": inspiration_market,
                "date_month": date_month,
                "categories": categories,
                "project_markets": project_markets,
                "prev_month": prev_month,
                "limit": limit,
                "offset": offset
            }
        })
        
    except Exception as e:
        print(f"Error fetching brand trends: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Failed to fetch brand trends: {str(e)}"
        }), 500

@app.route("/api/user/trendspotting-preferences", methods=["GET"])
@token_required
def get_trendspotting_preferences(current_user):
    """Get the filter preferences for the Brand Trends page"""
    try:
        # Get the user document from Firestore
        user_ref = firestore_client.collection('users').document(current_user)
        user_doc = user_ref.get()
        
        if not user_doc.exists:
            return jsonify({
                "success": False,
                "error": "User document not found"
            }), 404
        
        # Get the trendspotting_preferences from the user document (default to empty dict)
        user_data = user_doc.to_dict()
        trendspotting_preferences = user_data.get('trendspotting_preferences', {})
        
        # If no preferences found, apply defaults
        if not trendspotting_preferences:
            # Default to US as inspiration market
            trendspotting_preferences = {
                "selectedInspirationMarkets": ["US"],
                "selectedProjectMarkets": [],  # Will be populated client-side with up to 3 available markets
                "selectedInspirationCategories": []
            }
            
        return jsonify({
            "success": True,
            "data": trendspotting_preferences
        })
    except Exception as e:
        print(f"Error getting trendspotting preferences: {str(e)}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route("/api/user/trendspotting-preferences", methods=["POST"])
@token_required
def save_trendspotting_preferences(current_user):
    """Save filter preferences for the Brand Trends page"""
    try:
        # Get request data
        data = request.get_json()
        
        if not data:
            return jsonify({
                "success": False,
                "error": "Missing required data"
            }), 400
        
        # Clean the preferences to only include necessary fields
        preferences = {
            # Handle both single and multi-select for inspiration markets
            "selectedInspirationMarkets": data.get("selectedInspirationMarkets", []),
            
            # Handle multi-select for project markets
            "selectedProjectMarkets": data.get("selectedProjectMarkets", []),
            
            # Handle multi-select for inspiration categories
            "selectedInspirationCategories": data.get("selectedInspirationCategories", [])
        }
        
        # Get the user document from Firestore
        user_ref = firestore_client.collection('users').document(current_user)
        user_doc = user_ref.get()
        
        if not user_doc.exists:
            return jsonify({
                "success": False,
                "error": "User document not found"
            }), 404
        
        # Update the trendspotting preferences
        user_ref.update({
            "trendspotting_preferences": preferences,
            "updated_at": firestore.SERVER_TIMESTAMP
        })
        
        return jsonify({
            "success": True,
            "message": "Trendspotting preferences saved successfully",
            "data": preferences
        })
    except Exception as e:
        print(f"Error saving trendspotting preferences: {str(e)}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route("/api/brand-trends/sparklines", methods=["GET"])
@token_required
@project_access_required
def get_brand_sparklines(current_user, cloud_project_id=None):

    try:
        # ───────────────────────────────
        # 1. basic argument validation
        # ───────────────────────────────
        brands_raw          = request.args.get("brands")
        inspiration_market  = request.args.get("inspiration_market")
        date_month          = request.args.get("date_month")
        categories          = request.args.getlist("categories[]")

        if not all([brands_raw, inspiration_market, date_month]):
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "Missing required parameters: brands, inspiration_market, and date_month",
                    }
                ),
                400,
            )

        brands = [b.strip() for b in brands_raw.split(",") if b.strip()]
        if len(brands) > 1000:                      # safeguard – BigQuery caps array size at 100k, but keep memory low
            brands = brands[:1000]

        try:
            end_date   = datetime.strptime(date_month, "%Y-%m-%d")
            start_date = (end_date.replace(day=1) - timedelta(days=366)).replace(day=1)
        except ValueError:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": f"Invalid date format: {date_month}. Expected YYYY-MM-DD.",
                    }
                ),
                400,
            )

        # ───────────────────────────────
        # 2. optional category handling
        # ───────────────────────────────
        category_mapping = {
            "Office Supplies": 922, "Food, Beverages & Tobacco": 412, "Religious & Ceremonial": 5605,
            "Vehicles & Parts": 888, "Business & Industrial": 111, "Software": 2092, "Toys & Games": 1239,
            "Hardware": 632, "Baby & Toddler": 537, "Luggage & Bags": 5181, "Animals & Pet Supplies": 1,
            "Apparel & Accessories": 166, "Furniture": 436, "Arts & Entertainment": 8, "Sporting Goods": 988,
            "Home & Garden": 536, "Health & Beauty": 469, "Media": 783, "Cameras & Optics": 141,
            "Mature": 772, "Electronics": 222,
        }
        category_ids = [category_mapping[c] for c in categories if c in category_mapping]

        # ───────────────────────────────
        # 3. parameterised BigQuery
        # ───────────────────────────────
        query = f"""
        SELECT
          EXTRACT(DATE FROM TIMESTAMP_TRUNC(_PARTITIONTIME, DAY)) AS date,
          brand,
          rank
        FROM `s360-demand-sensing.ds_master_raw_data.BestSellersBrandMonthly_11097323`
        WHERE LOWER(brand) IN UNNEST(@brand_list)
          AND country_code = @market
          {"AND category_id IN UNNEST(@category_ids)" if category_ids else ""}
          AND EXTRACT(DATE FROM TIMESTAMP_TRUNC(_PARTITIONTIME, DAY))
                BETWEEN @start_date AND @end_date
        ORDER BY date, brand
        """

        params = [
            bigquery.ArrayQueryParameter("brand_list", "STRING", [b.lower() for b in brands]),
            bigquery.ScalarQueryParameter("market", "STRING", inspiration_market),
            bigquery.ScalarQueryParameter("start_date", "DATE", start_date.date()),
            bigquery.ScalarQueryParameter("end_date", "DATE", end_date.date()),
        ]
        if category_ids:
            params.append(bigquery.ArrayQueryParameter("category_ids", "INT64", category_ids))

        job_config = bigquery.QueryJobConfig(query_parameters=params)
        results = bigquery_client.query(query, job_config=job_config).result()
        # ───────────────────────────────
        # 4. build response payload
        # ───────────────────────────────
        sparkline_data = {}
        for row in results:
            brand = row.brand
            sparkline_data.setdefault(brand, []).append(
                {
                    "date": row.date.isoformat(),
                    "rank": row.rank,
                    # invert + cap so better rank draws higher point
                    "value": 100 - min(row.rank, 100),
                }
            )

        for series in sparkline_data.values():
            series.sort(key=lambda p: p["date"])

        return jsonify({"success": True, "sparkline_data": sparkline_data})

    except Exception as exc:
        # Log full traceback in real application logs
        print(f"Error fetching brand sparklines: {exc}")
        return (
            jsonify({"success": False, "error": f"Failed to fetch brand sparklines: {exc}"}),
            500,
        )

# If we're running this directly, then run the Flask app
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
