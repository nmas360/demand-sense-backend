from flask import Blueprint
from utils.imports import *
from utils.config import *
from utils.decorators import *
from urllib.parse import quote


product_discovery_performance_bp = Blueprint('product_discovery_performance', __name__)


@product_discovery_performance_bp.route("/api/admin/product-discovery-performance-analysis", methods=["GET"])
def analyze_product_discovery_performance(current_user=""):
    # Get project_id from request params if provided
    project_id = request.args.get("project_id")
    
    # If project_id is not provided, require scheduler token authentication
    if not project_id:
        scheduler_token = os.environ.get("SCHEDULER_TOKEN")
        if not scheduler_token:
            logging.error("SCHEDULER_TOKEN environment variable is not set")
            return jsonify({"error": "Server configuration error"}), 500
            
        auth_header = request.headers.get("Authorization")
        expected_auth = f"Bearer {scheduler_token}"
        
        if not auth_header or auth_header != expected_auth:
            logging.warning("Unauthorized attempt to access category assortment analysis")
            return jsonify({"error": "Unauthorized"}), 401
    
    #print(f"Starting product discovery performance analysis...")
    master_project_id = "s360-demand-sensing"

    try:
        dataset_ref = bigquery_client.dataset("project_performance", project=master_project_id)

        # Check if table exists, create if it doesn't
        bigquery_client.get_dataset(dataset_ref)
        table_ref = bigquery_client.dataset("project_performance").table("product_discovery_performance")

        try:
            bigquery_client.get_table(table_ref)
            print(f"Table {master_project_id}.project_performance.product_discovery_performance exists")
        except NotFound:
            print(f"Table {master_project_id}.project_performance.product_discovery_performance not found, creating...")
            # Define updated schema with new fields
            schema = [
                bigquery.SchemaField("timestamp", "TIMESTAMP", mode="REQUIRED"),
                bigquery.SchemaField("project_id", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("cloud_project_id", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("merchant_center_id", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("country_code_bs", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("category", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("bestseller_date", "DATE", mode="REQUIRED"),
                bigquery.SchemaField("mc_products_date", "DATE", mode="REQUIRED"),
                bigquery.SchemaField("is_top_category", "BOOLEAN", mode="NULLABLE"),
                bigquery.SchemaField("products_in_assortment", "INTEGER", mode="NULLABLE"),
                bigquery.SchemaField("products_in_stock", "INTEGER", mode="NULLABLE"),
                bigquery.SchemaField("products_out_stock", "INTEGER", mode="NULLABLE"),
                bigquery.SchemaField("total_products", "INTEGER", mode="NULLABLE"),
                bigquery.SchemaField("share_percentage", "FLOAT", mode="NULLABLE"),
                bigquery.SchemaField("backfill", "BOOLEAN", mode="REQUIRED")
            ]
            
            table = bigquery.Table(table_ref, schema=schema)
            table.time_partitioning = bigquery.TimePartitioning(
                type_=bigquery.TimePartitioningType.DAY,
                field="bestseller_date"
            )
            table.clustering_fields = ["project_id", "merchant_center_id", "country_code_bs"]
            table = bigquery_client.create_table(table)
            print(f"Created table {table.project}.{table.dataset_id}.{table.table_id}")
            
    except Exception as table_error:
        print(f"Error creating/checking BigQuery table: {str(table_error)}")
        # Continue processing even if table creation fails
    
    projects_ref = firestore_client.collection('client_projects')
    
    # If project_id is provided, only process that project
    if project_id:
        project_doc = projects_ref.document(project_id).get()
        if not project_doc.exists:
            return jsonify({"error": f"Project with ID {project_id} not found"}), 404
        projects = [project_doc]
        print(f"Processing single project with ID: {project_id}")
    else:
        # Process all projects (scheduler mode)
        projects = list(projects_ref.stream())
        print(f"Processing all {len(projects)} projects (scheduler mode)")

    all_results = []
    processed_results = []

    for project_doc in projects:
        project_data = project_doc.to_dict()
        project_id = project_doc.id
        cloud_project_id = project_data.get('cloudProjectId')
        merchant_centers = project_data.get('merchantCenters', [])

        # Skip if no cloud project ID or merchant centers
        if not cloud_project_id or not merchant_centers:
            print(f"Skipping project {project_id}: missing cloud_project_id or merchant_centers")
            continue

        #print(f"Processing project {project_id} ({project_data.get('name', 'Unknown')})")
        project_result = {
            "project_id": project_id,
            "project_name": project_data.get('name', 'Unknown'),
            "cloud_project_id": cloud_project_id,
            "merchant_centers": []
        }

        for mc in merchant_centers:
            merchant_center_id = mc.get('merchantCenterId')
            feed_label_country_code = mc.get('code', '').lower()
            bestseller_country_code = mc.get('mappedMarket', feed_label_country_code).upper() if mc.get('mappedMarket') else feed_label_country_code.upper()
            
            if not merchant_center_id or not feed_label_country_code:
                print(f"Skipping merchant center: missing merchantCenterId or code")
                continue
                
            #print(f"Processing merchant center {merchant_center_id} for country {bestseller_country_code}")
            project_result["merchant_centers"].append({
                "merchant_center_id": merchant_center_id,
                "feed_label_country_code": feed_label_country_code, # code from firestore
                "bestseller_country_code": bestseller_country_code, # mappedMarket from firestore
            })
            
            # Get the latest date for which we've already processed data for this merchant center
            try:
                latest_processed_query = f"""
                SELECT MAX(bestseller_date) as latest_date
                FROM `{master_project_id}.project_performance.product_discovery_performance`
                WHERE project_id = '{project_id}'
                AND merchant_center_id = '{merchant_center_id}'
                AND country_code_bs = '{bestseller_country_code}'
                """
                
                latest_processed_job = bigquery_client.query(latest_processed_query)
                latest_processed_result = latest_processed_job.result()
                latest_processed_date = None
                
                for row in latest_processed_result:
                    latest_processed_date = row.latest_date
                    break
                
                #print(f"Latest processed date for {merchant_center_id}: {latest_processed_date}")
                
                # Get available bestseller dates that need processing
                bestseller_dates_query = f"""
                SELECT DISTINCT date_month
                FROM `s360-demand-sensing.ds_master_transformed_data.bestseller_monthly`
                WHERE country_code = '{bestseller_country_code}'
                """
                
                if latest_processed_date:
                    bestseller_dates_query += f" AND date_month > '{latest_processed_date}'"
                
                bestseller_dates_query += " ORDER BY date_month"
                
                bestseller_dates_job = bigquery_client.query(bestseller_dates_query)
                bestseller_dates_result = bestseller_dates_job.result()
                
                dates_to_process = []
                for date_row in bestseller_dates_result:
                    dates_to_process.append(date_row.date_month)
                
                #print(f"Found {len(dates_to_process)} bestseller dates to process for {merchant_center_id}")
                
                for bestseller_date in dates_to_process:
                    #print(f"Processing date {bestseller_date} for {merchant_center_id}")
                    
                    # Get latest Products data date for this merchant center
                    products_date_query = f"""
                    SELECT MAX(_PARTITIONTIME) as latest_date
                    FROM `{cloud_project_id}.ds_raw_data.Products_{merchant_center_id}`
                    """
                    
                    products_date_job = bigquery_client.query(products_date_query)
                    products_date_result = products_date_job.result()
                    products_date = None
                    
                    for row in products_date_result:
                        products_date = row.latest_date
                        break
                    
                    if not products_date:
                        print(f"No products data found for {merchant_center_id}")
                        continue
                    
                    # Get the first day of the bestseller month to check for backfill
                    bestseller_month_first_day = None
                    if hasattr(bestseller_date, 'year') and hasattr(bestseller_date, 'month'):
                        # Bestseller date is already a date object
                        bestseller_month_first_day = datetime(bestseller_date.year, bestseller_date.month, 1).date()
                    else:
                        # Try to parse the bestseller_date if it's a string
                        try:
                            parsed_date = datetime.strptime(str(bestseller_date), '%Y-%m-%d').date()
                            bestseller_month_first_day = datetime(parsed_date.year, parsed_date.month, 1).date()
                        except Exception as e:
                            print(f"Unable to parse bestseller_date {bestseller_date} to determine month's first day: {str(e)}")
                    
                    # Check if we have product data for the first day of bestseller month
                    first_day_data_exists = False
                    backfill = True
                    
                    if bestseller_month_first_day:
                        first_day_check_query = f"""
                        SELECT COUNT(*) as count
                        FROM `{cloud_project_id}.ds_raw_data.Products_{merchant_center_id}`
                        WHERE _PARTITIONTIME = '{bestseller_month_first_day}'
                        """
                        
                        first_day_check_job = bigquery_client.query(first_day_check_query)
                        first_day_check_result = first_day_check_job.result()
                        
                        for row in first_day_check_result:
                            if row.count > 0:
                                first_day_data_exists = True
                                break
                    
                    # If we have data for the first day of the month, use that instead of the latest
                    if first_day_data_exists:
                        products_date = bestseller_month_first_day
                        backfill = False
                        #print(f"Using first day of bestseller month data ({products_date}) for {merchant_center_id}")
                    #else:
                    #    print(f"Using latest products data ({products_date}) for {merchant_center_id} (backfill=True)")
                    
                    # Run the main query to get category performance data
                    query = f"""
                    WITH products AS (
                      SELECT
                        m.entity_id,
                        MAX(CASE WHEN p.availability = 'in stock' THEN 1 ELSE 0 END) AS in_stock,
                        CASE
                          WHEN MAX(CASE WHEN p.availability = 'in stock' THEN 1 ELSE 0 END) = 0
                          THEN 1 ELSE 0
                        END AS out_of_stock,
                        1 AS in_assortment
                      FROM `{cloud_project_id}.ds_raw_data.Products_{merchant_center_id}` p
                      INNER JOIN `{cloud_project_id}.ds_raw_data.BestSellersEntityProductMapping_{merchant_center_id}` m
                            ON LOWER(p.product_id) = LOWER(m.product_id)
                      WHERE p._PARTITIONTIME = '{products_date}'
                        AND channel = 'online'
                        AND LOWER(feed_label) = '{feed_label_country_code}'
                      GROUP BY m.entity_id
                    ),
                    bestseller_main AS (
                      SELECT DISTINCT
                        entity_id,
                        category
                      FROM `s360-demand-sensing.ds_master_transformed_data.bestseller_monthly`
                      WHERE date_month = '{bestseller_date}' 
                        AND country_code = '{bestseller_country_code}' 
                    ),
                    merge_data AS (
                      SELECT
                        b.category,
                        SUM(IFNULL(p.in_stock, 0)) AS in_stock_count,
                        SUM(IFNULL(p.out_of_stock, 0)) AS out_of_stock_count,
                        SUM(IFNULL(p.in_assortment, 0)) AS in_assortment_count,
                        COUNT(*) AS total_product_count
                      FROM bestseller_main b
                      LEFT JOIN products p USING (entity_id)
                      GROUP BY b.category
                    )
                    SELECT *
                    FROM merge_data
                    """
                    #print(query)
                    try:
                        #print(f"Executing query for {merchant_center_id}, date {bestseller_date}")
                        # Execute query
                        category_performance_job = bigquery_client.query(query)
                        category_performance_results = category_performance_job.result()
                        
                        # Process results and identify top category
                        category_results = []
                        top_category = None
                        max_in_assortment = -1
                        
                        row_count = 0
                        for row in category_performance_results:
                            row_count += 1
                            if not row.category:
                                #print(f"Skipping row with null category")
                                continue
                                
                            if row.total_product_count <= 0:
                                #print(f"Skipping category {row.category} with zero or negative total_product_count")
                                continue
                            
                            # Safety check for None values
                            in_stock_count = 0 if row.in_stock_count is None else row.in_stock_count
                            out_of_stock_count = 0 if row.out_of_stock_count is None else row.out_of_stock_count
                            in_assortment_count = 0 if row.in_assortment_count is None else row.in_assortment_count
                            total_product_count = row.total_product_count
                            
                            # Calculate share percentage with safety check
                            share_percentage = 0
                            if total_product_count > 0 and in_assortment_count is not None:
                                share_percentage = in_assortment_count / total_product_count
                            
                            category_result = {
                                "category": row.category,
                                "products_in_stock": in_stock_count,
                                "products_out_stock": out_of_stock_count,
                                "products_in_assortment": in_assortment_count,
                                "total_products": total_product_count,
                                "share_percentage": share_percentage
                            }
                            
                            category_results.append(category_result)
                            
                            # Update top category if this one has more products in assortment
                            if in_assortment_count > max_in_assortment:
                                max_in_assortment = in_assortment_count
                                top_category = row.category
                        
                        #print(f"Processed {row_count} rows, found {len(category_results)} valid categories for {merchant_center_id}")
                        
                        # Insert results into BigQuery
                        if category_results:
                            rows_to_insert = []
                            current_timestamp = datetime.now()
                            
                            for category_result in category_results:
                                is_top = category_result["category"] == top_category
                                
                                # Convert datetime objects to ISO format strings for JSON serialization
                                formatted_timestamp = current_timestamp.isoformat()
                                
                                # Format date fields as YYYY-MM-DD for BigQuery DATE type
                                if hasattr(bestseller_date, 'strftime'):
                                    formatted_bestseller_date = bestseller_date.strftime('%Y-%m-%d')
                                else:
                                    # Handle if it's already a string or other format
                                    formatted_bestseller_date = str(bestseller_date)
                                
                                if hasattr(products_date, 'strftime'):
                                    formatted_products_date = products_date.strftime('%Y-%m-%d')
                                else:
                                    # Handle if it's already a string or other format
                                    formatted_products_date = str(products_date)
                            
                                row = {
                                    "timestamp": formatted_timestamp,
                                    "project_id": project_id,
                                    "cloud_project_id": cloud_project_id,
                                    "merchant_center_id": merchant_center_id,
                                    "country_code_bs": bestseller_country_code,
                                    "category": category_result["category"],
                                    "bestseller_date": formatted_bestseller_date,
                                    "mc_products_date": formatted_products_date,
                                    "backfill": backfill,
                                    "is_top_category": is_top,
                                    "products_in_assortment": category_result["products_in_assortment"],
                                    "products_in_stock": category_result["products_in_stock"],
                                    "products_out_stock": category_result["products_out_stock"],
                                    "total_products": category_result["total_products"],
                                    "share_percentage": category_result["share_percentage"]
                                }
                                
                                rows_to_insert.append(row)
                            
                            # Insert rows
                            if rows_to_insert:
                                #print(f"Inserting {len(rows_to_insert)} rows for {merchant_center_id}, date {bestseller_date}")
                                insert_errors = bigquery_client.insert_rows_json(
                                    f"{master_project_id}.project_performance.product_discovery_performance",
                                    rows_to_insert
                                )
                                
                                if insert_errors:
                                    print(f"Errors inserting rows for {merchant_center_id}: {insert_errors}")
                                else:
                                    #print(f"Successfully inserted {len(rows_to_insert)} rows for {merchant_center_id}")
                                    processed_date_info = {
                                        "project_id": project_id,
                                        "merchant_center_id": merchant_center_id,
                                        "bestseller_country_code": bestseller_country_code,
                                        "bestseller_date": bestseller_date.strftime('%Y-%m-%d') if hasattr(bestseller_date, 'strftime') else str(bestseller_date),
                                        "categories_processed": len(category_results),
                                        "top_category": top_category
                                    }
                                    processed_results.append(processed_date_info)
                                
                    except Exception as query_error:
                        error_msg = f"Error processing data for project {project_id}, merchant center {merchant_center_id}, date {bestseller_date}: {str(query_error)}"
                        print(error_msg)
                        traceback.print_exc()  # Print the full stack trace for better debugging
                
            except Exception as mc_error:
                error_msg = f"Error processing merchant center {merchant_center_id}: {str(mc_error)}"
                print(error_msg)
                traceback.print_exc()  # Print the full stack trace for better debugging

        all_results.append(project_result)

    print(f"Analysis complete. Processed {len(processed_results)} dates across all merchant centers")
    return jsonify({
        "projects": all_results,
        "processed_data": processed_results
    })




    
@product_discovery_performance_bp.route("/api/data/category-trend", methods=["GET"])
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

@product_discovery_performance_bp.route("/api/performance/category-demand", methods=["GET"])
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

@product_discovery_performance_bp.route("/api/performance/market-share", methods=["GET"])
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

@product_discovery_performance_bp.route("/api/assortment/category-products", methods=["GET"])
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
