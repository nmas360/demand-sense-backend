from flask import Blueprint
from utils.imports import *
from utils.config import *
from utils.decorators import *
from urllib.parse import quote

# Create the auth blueprint
admin_bp = Blueprint('admin', __name__)



@admin_bp.route("/api/verify-permissions", methods=["POST"])
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

@admin_bp.route("/api/client-projects", methods=["POST"])
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
    

    
@admin_bp.route("/api/client-projects/<project_id>", methods=["DELETE"])
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

@admin_bp.route("/api/client-projects/<project_id>", methods=["PUT"])
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

@admin_bp.route("/api/client-projects/<project_id>", methods=["GET"])
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



@admin_bp.route("/api/client-projects/create-data-transfer", methods=["POST"])
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

@admin_bp.route("/api/verify-merchant-connection", methods=["POST"])
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


@admin_bp.route("/api/client-projects/<project_id>/transfers", methods=["GET"])
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

@admin_bp.route("/api/client-projects/check-setup-status", methods=["GET"])
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



@admin_bp.route("/api/admin/login-activity", methods=["GET"])
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
    


@admin_bp.route("/api/admin/project-billing", methods=["GET"])
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
