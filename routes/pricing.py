from flask import Blueprint
from utils.imports import *
from utils.config import *
from utils.decorators import *
from urllib.parse import quote

# Create the auth blueprint
pricing_bp = Blueprint('pricing', __name__)



@pricing_bp.route("/api/pricing", methods=["GET"])
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
        
        # Get country code filter parameter
        country_code = request.args.get('code', None)
        # Get mappedMarket filter parameter
        mapped_market = request.args.get('mappedMarket', None)

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
        
        # Country code filter clause for last7days (uses mappedMarket)
        country_code_clause_last7days = ""
        if mapped_market:
            # Handle special case where mappedMarket is '-'
            if mapped_market == '-':
                print(f"Received special mappedMarket '-' - not applying country filter for last7days")
                # Don't apply country filter in this case
            else:
                safe_mapped_market = mapped_market.replace("'", "''")
                country_code_clause_last7days = f"AND LOWER(customer_country_code) = LOWER('{safe_mapped_market}')"
                print(f"Applied country filter with mappedMarket: {safe_mapped_market} for last7days")
        elif country_code:
            # Fallback to code if mappedMarket is not provided
            if country_code == '-':
                print(f"Received special code '-' - not applying country filter for last7days")
            else:
                safe_country_code = country_code.replace("'", "''")
                country_code_clause_last7days = f"AND LOWER(customer_country_code) = LOWER('{safe_country_code}')"
                print(f"Applied country filter with code (fallback): {safe_country_code} for last7days")
        
        # Country code filter clause for insights (uses code)
        country_code_clause_insights = ""
        if country_code:
            # Handle special case where code is '-'
            if country_code == '-':
                print(f"Received special code '-' - not applying country filter for insights")
                # Don't apply country filter in this case
            else:
                safe_country_code = country_code.replace("'", "''")
                country_code_clause_insights = f"AND LOWER(SPLIT(LEFT(id, 13), \":\")[OFFSET(2)]) = LOWER('{safe_country_code}')"
                print(f"Applied country filter with code: {safe_country_code} for insights")
        
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
          {country_code_clause_last7days}
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
          {country_code_clause_insights}
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
          {country_code_clause_last7days}
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
          {country_code_clause_insights}
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
          {country_code_clause_insights}
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
        {country_code_clause_last7days}
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
    


@pricing_bp.route("/api/pricing/filters", methods=["GET"])
@token_required
@project_access_required
def get_pricing_filters(current_user, cloud_project_id = None):
    """Get filter options for pricing data (product types, brands, price range)"""
    try:
        from concurrent.futures import ThreadPoolExecutor
        
        # Get merchant center ID if provided
        merchant_center_id = request.args.get('merchant_center_id', None)
        
        # Get country code filter parameter
        country_code = request.args.get('code', None)
        # Get mappedMarket filter parameter
        mapped_market = request.args.get('mappedMarket', None)

        # Validation: ensure we have the required parameters
        if not merchant_center_id or not cloud_project_id:
            return jsonify({
                "success": False,
                "error": "Missing required parameters: merchant_center_id and project_id"
            }), 400
        
        # Country code filter clause for last7days (uses mappedMarket)
        country_code_clause_last7days = ""
        if mapped_market:
            # Handle special case where mappedMarket is '-'
            if mapped_market == '-':
                print(f"Received special mappedMarket '-' - not applying country filter for last7days")
                # Don't apply country filter in this case
            else:
                safe_mapped_market = mapped_market.replace("'", "''")
                country_code_clause_last7days = f"AND LOWER(customer_country_code) = LOWER('{safe_mapped_market}')"
                print(f"Applied country filter with mappedMarket: {safe_mapped_market} for last7days")
        elif country_code:
            # Fallback to code if mappedMarket is not provided
            if country_code == '-':
                print(f"Received special code '-' - not applying country filter for last7days")
            else:
                safe_country_code = country_code.replace("'", "''")
                country_code_clause_last7days = f"AND LOWER(customer_country_code) = LOWER('{safe_country_code}')"
                print(f"Applied country filter with code (fallback): {safe_country_code} for last7days")
        
        # Country code filter clause for insights (uses code)
        country_code_clause_insights = ""
        if country_code:
            # Handle special case where code is '-'
            if country_code == '-':
                print(f"Received special code '-' - not applying country filter for insights")
                # Don't apply country filter in this case
            else:
                safe_country_code = country_code.replace("'", "''")
                country_code_clause_insights = f"AND LOWER(SPLIT(LEFT(id, 13), \":\")[OFFSET(2)]) = LOWER('{safe_country_code}')"
                print(f"Applied country filter with code: {safe_country_code} for insights")
        
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
          {country_code_clause_insights}
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
        {country_code_clause_last7days}
        ORDER BY product_type_l1, product_type_l2, product_type_l3
        """
        
        # Define query for brands
        brands_query = f"""
        SELECT DISTINCT brand
        FROM `{cloud_project_id}.ds_raw_data.ProductPerformance_{merchant_center_id}`
        WHERE DATE(_PARTITIONTIME) BETWEEN DATE_SUB(CURRENT_DATE(), INTERVAL 6 DAY) AND CURRENT_DATE()
        AND brand IS NOT NULL AND brand != ''
        {country_code_clause_last7days}
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

@pricing_bp.route("/api/streams", methods=["GET"])
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

@pricing_bp.route("/api/streams", methods=["POST"])
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
        
        # Get filters with both code and mappedMarket
        filters = data["filters"]
        
        # Ensure both code and mappedMarket are included in the filters
        # If mappedMarket is not provided but code is, use code as mappedMarket
        if "code" in filters and "mappedMarket" not in filters:
            filters["mappedMarket"] = filters["code"]
        # If code is not provided but mappedMarket is, store mappedMarket but don't use it as code
        # as code needs to be the actual country code
        
        # Create new stream document
        new_stream = {
            "name": data["name"],
            "description": data.get("description", ""),
            "project_id": data["project_id"],
            "merchant_center_id": data["merchant_center_id"],
            "filters": filters,
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

@pricing_bp.route("/api/streams/<stream_id>", methods=["PUT"])
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
                # Special handling for filters to ensure mappedMarket is included
                if field == "filters" and data[field]:
                    filters = data[field]
                    
                    # Ensure both code and mappedMarket are included in the filters
                    # If mappedMarket is not provided but code is, use code as mappedMarket
                    if "code" in filters and "mappedMarket" not in filters:
                        filters["mappedMarket"] = filters["code"]
                    
                    update_data[field] = filters
                else:
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

@pricing_bp.route("/api/streams/<stream_id>", methods=["DELETE"])
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
@pricing_bp.route("/public/stream/<stream_id>", methods=["GET"])
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
        
        # Get country code from filters
        country_code = filters.get('code')
        # Get mappedMarket from filters (could be the same as code if not explicitly set)
        mapped_market = filters.get('mappedMarket', country_code)
        
        # Country code filter clause for last7days (uses mappedMarket)
        country_code_clause_last7days = ""
        if mapped_market:
            # Handle special case where mappedMarket is '-'
            if mapped_market == '-':
                print(f"Received special mappedMarket '-' - not applying country filter for stream last7days")
                # Don't apply country filter in this case
            else:
                safe_mapped_market = mapped_market.replace("'", "''")
                country_code_clause_last7days = f"AND LOWER(customer_country_code) = LOWER('{safe_mapped_market}')"
                print(f"Applied country filter with mappedMarket: {safe_mapped_market} for stream last7days")
        elif country_code:
            # Fallback to code if mappedMarket is not provided
            if country_code == '-':
                print(f"Received special code '-' - not applying country filter for stream last7days")
            else:
                safe_country_code = country_code.replace("'", "''")
                country_code_clause_last7days = f"AND LOWER(customer_country_code) = LOWER('{safe_country_code}')"
                print(f"Applied country filter with code (fallback): {safe_country_code} for stream last7days")
        
        # Country code filter clause for insights (uses code)
        country_code_clause_insights = ""
        if country_code:
            # Handle special case where code is '-'
            if country_code == '-':
                print(f"Received special code '-' - not applying country filter for stream insights")
                # Don't apply country filter in this case
            else:
                safe_country_code = country_code.replace("'", "''")
                country_code_clause_insights = f"AND LOWER(SPLIT(LEFT(id, 13), \":\")[OFFSET(2)]) = LOWER('{safe_country_code}')"
                print(f"Applied country filter with code: {safe_country_code} for stream insights")
        
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
          {country_code_clause_last7days}
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
          {country_code_clause_insights}
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