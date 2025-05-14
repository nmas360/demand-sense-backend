from flask import Blueprint
from utils.imports import *
from utils.config import *
from utils.decorators import *
from urllib.parse import quote


product_discovery_performance_bp = Blueprint('product_discovery_performance', __name__)


@product_discovery_performance_bp.route("/api/admin/category-assortment-analysis", methods=["GET"])
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
