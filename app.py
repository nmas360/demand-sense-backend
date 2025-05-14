# Import modules from utils
from utils.imports import *
from utils.config import *
from utils.decorators import *


# Import the auth blueprint
from routes.auth import auth_bp
from routes.admin import admin_bp
from routes.product_discovery import product_discovery_bp
from routes.pricing import pricing_bp
from routes.trendspotting_brand_trends import trendspotting_brand_trends_bp
from routes.product_discovery_performance import product_discovery_performance_bp


# Initialize Flask app
app = Flask(__name__)
app.secret_key = SECRET_KEY  # for session

# Enable CORS for all routes
CORS(app)

# Register the auth blueprint with a URL prefix
app.register_blueprint(auth_bp)
app.register_blueprint(pricing_bp)
app.register_blueprint(product_discovery_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(trendspotting_brand_trends_bp)
app.register_blueprint(product_discovery_performance_bp)


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


# If we're running this directly, then run the Flask app
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
