from utils.imports import *
from utils.config import *

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