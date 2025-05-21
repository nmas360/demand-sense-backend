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
                bigquery.SchemaField("products_rank_below_10", "INTEGER", mode="NULLABLE"),
                bigquery.SchemaField("products_rank_below_50", "INTEGER", mode="NULLABLE"),
                bigquery.SchemaField("products_rank_below_100", "INTEGER", mode="NULLABLE"),
                bigquery.SchemaField("products_rank_below_250", "INTEGER", mode="NULLABLE"),
                bigquery.SchemaField("products_rank_below_500", "INTEGER", mode="NULLABLE"),
                bigquery.SchemaField("products_rank_below_1000", "INTEGER", mode="NULLABLE"),
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
                        category,
                        CAST(rank AS INT64) AS rank
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
                        COUNT(*) AS total_product_count,
                        SUM(CASE WHEN b.rank < 10 AND p.in_assortment = 1 THEN 1 ELSE 0 END) AS products_rank_below_10,
                        SUM(CASE WHEN b.rank < 50 AND p.in_assortment = 1 THEN 1 ELSE 0 END) AS products_rank_below_50,
                        SUM(CASE WHEN b.rank < 100 AND p.in_assortment = 1 THEN 1 ELSE 0 END) AS products_rank_below_100,
                        SUM(CASE WHEN b.rank < 250 AND p.in_assortment = 1 THEN 1 ELSE 0 END) AS products_rank_below_250,
                        SUM(CASE WHEN b.rank < 500 AND p.in_assortment = 1 THEN 1 ELSE 0 END) AS products_rank_below_500,
                        SUM(CASE WHEN b.rank < 1000 AND p.in_assortment = 1 THEN 1 ELSE 0 END) AS products_rank_below_1000
                      FROM bestseller_main b
                      LEFT JOIN products p USING (entity_id)
                      GROUP BY b.category
                    )
                    SELECT *
                    FROM merge_data
                    """
                    
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
                                "share_percentage": share_percentage,
                                "products_rank_below_10": row.products_rank_below_10 if hasattr(row, 'products_rank_below_10') else 0,
                                "products_rank_below_50": row.products_rank_below_50 if hasattr(row, 'products_rank_below_50') else 0,
                                "products_rank_below_100": row.products_rank_below_100 if hasattr(row, 'products_rank_below_100') else 0,
                                "products_rank_below_250": row.products_rank_below_250 if hasattr(row, 'products_rank_below_250') else 0,
                                "products_rank_below_500": row.products_rank_below_500 if hasattr(row, 'products_rank_below_500') else 0,
                                "products_rank_below_1000": row.products_rank_below_1000 if hasattr(row, 'products_rank_below_1000') else 0
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
                                    "share_percentage": category_result["share_percentage"],
                                    "products_rank_below_10": category_result["products_rank_below_10"],
                                    "products_rank_below_50": category_result["products_rank_below_50"],
                                    "products_rank_below_100": category_result["products_rank_below_100"],
                                    "products_rank_below_250": category_result["products_rank_below_250"],
                                    "products_rank_below_500": category_result["products_rank_below_500"],
                                    "products_rank_below_1000": category_result["products_rank_below_1000"]
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


@product_discovery_performance_bp.route("/api/performance/scorecards", methods=["GET"])
@token_required
@project_access_required
def get_performance_scorecards(current_user, cloud_project_id=None):
    """
    Get performance scorecards data for the Performance dashboard.
    Required query parameters:
    - country: The country code(s) to filter by (comma-separated for multiple countries)
    - project_id: The Firestore project ID to filter by
    Optional query parameters:
    - categories: Comma-separated list of categories to filter by
    """
    try:
        # Get parameters from request
        countries_param = request.args.get("country")
        categories_param = request.args.get("categories")
        
        # Validate country parameter
        if not countries_param:
            return jsonify({"error": "Country parameter is required"}), 400
            
        # Parse countries from comma-separated list
        countries = [country.strip() for country in countries_param.split(",")]
        if not countries:
            return jsonify({"error": "At least one valid country is required"}), 400
            
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
        
        # Create countries clause for SQL IN statement
        countries_clause = ", ".join([f"'{country}'" for country in countries])
        
        # Build the query to get scorecards data with current and previous month metrics
        query = f"""
        WITH all_data AS (
            SELECT DISTINCT
                bestseller_date,
                country_code_bs,
                category,
                share_percentage,
                total_products,
                products_in_assortment,
                products_out_stock
            FROM `s360-demand-sensing.project_performance.product_discovery_performance`
            WHERE project_id = '{project_id}'
            AND products_in_assortment > 0
            AND country_code_bs IN ({countries_clause})
        """
        
        # Add category filter if provided
        if categories and len(categories) > 0:
            category_conditions = ", ".join([f"'{cat.strip()}'" for cat in categories])
            query += f"AND category IN ({category_conditions})"
        
        # Close the all_data CTE
        query += """
        ),
        
        -- Get the latest two months of data
        date_ranks AS (
            SELECT 
                bestseller_date,
                DENSE_RANK() OVER (ORDER BY bestseller_date DESC) as date_rank
            FROM all_data
            GROUP BY bestseller_date
        ),
        
        top_dates AS (
            SELECT bestseller_date, date_rank
            FROM date_ranks
            WHERE date_rank <= 2
        ),
        
        -- Join with data to get metrics for current and previous month
        monthly_data AS (
            SELECT 
                d.bestseller_date,
                d.country_code_bs,
                d.category,
                d.share_percentage,
                d.total_products - d.products_in_assortment AS products_outside_assortment,
                d.products_out_stock,
                td.date_rank
            FROM all_data d
            JOIN top_dates td ON d.bestseller_date = td.bestseller_date
        ),
        
        category_country_data AS (
            SELECT 
                bestseller_date,
                date_rank,
                country_code_bs,
                category,
                AVG(share_percentage) as share_percentage,
                SUM(products_outside_assortment) AS total_products_outside_assortment,
                SUM(products_out_stock) AS total_products_out_of_stock
            FROM monthly_data
            GROUP BY bestseller_date, date_rank, country_code_bs, category
        ),
        
        category_data AS (
            SELECT 
                bestseller_date,
                date_rank,
                category,
                AVG(share_percentage) as share_percentage,
                SUM(total_products_outside_assortment) AS total_products_outside_assortment,
                SUM(total_products_out_of_stock) AS total_products_out_of_stock
            FROM category_country_data
            GROUP BY bestseller_date, date_rank, category
        ),
        
        -- Aggregate by month
        aggregated_data AS (
            SELECT
                bestseller_date,
                date_rank,
                AVG(share_percentage) as avg_share_percentage,
                SUM(total_products_outside_assortment) as total_products_outside_assortment,
                SUM(total_products_out_of_stock) as total_products_out_of_stock
            FROM category_data
            GROUP BY bestseller_date, date_rank
        )
        
        -- Final result with current and previous month data
        SELECT
            current_month.bestseller_date as current_date,
            prev_month.bestseller_date as prev_date,
            current_month.avg_share_percentage as current_share_percentage,
            prev_month.avg_share_percentage as prev_share_percentage,
            CASE 
                WHEN prev_month.avg_share_percentage > 0 
                THEN (current_month.avg_share_percentage - prev_month.avg_share_percentage) / prev_month.avg_share_percentage
                ELSE NULL 
            END as share_percentage_growth,
            
            current_month.total_products_outside_assortment as current_products_outside_assortment,
            prev_month.total_products_outside_assortment as prev_products_outside_assortment,
            CASE 
                WHEN prev_month.total_products_outside_assortment > 0 
                THEN (current_month.total_products_outside_assortment - prev_month.total_products_outside_assortment) / prev_month.total_products_outside_assortment
                ELSE NULL 
            END as products_outside_assortment_growth,
            
            current_month.total_products_out_of_stock as current_products_out_of_stock,
            prev_month.total_products_out_of_stock as prev_products_out_of_stock,
            CASE 
                WHEN prev_month.total_products_out_of_stock > 0 
                THEN (current_month.total_products_out_of_stock - prev_month.total_products_out_of_stock) / prev_month.total_products_out_of_stock
                ELSE NULL 
            END as products_out_of_stock_growth
        FROM 
            aggregated_data current_month
        LEFT JOIN 
            aggregated_data prev_month ON current_month.date_rank = 1 AND prev_month.date_rank = 2
        WHERE 
            current_month.date_rank = 1
        """
        

        query_job = client.query(query)
        results = query_job.result()
        
        # Process the results
        scorecard_data = None
        
        for row in results:
            scorecard_data = {
                "bestseller_date": row.current_date.strftime("%Y-%m-%d") if row.current_date else None,
                "prev_bestseller_date": row.prev_date.strftime("%Y-%m-%d") if row.prev_date else None,
                
                # Current month metrics
                "avg_share_percentage": row.current_share_percentage,
                "total_products_outside_assortment": row.current_products_outside_assortment,
                "total_products_out_of_stock": row.current_products_out_of_stock,
                
                # Growth percentages
                "share_percentage_growth": row.share_percentage_growth,
                "products_outside_assortment_growth": row.products_outside_assortment_growth,
                "products_out_of_stock_growth": row.products_out_of_stock_growth
            }
            break
        
        # Return the data with defaults if no data was found
        if not scorecard_data:
            scorecard_data = {
                "bestseller_date": None,
                "prev_bestseller_date": None,
                "avg_share_percentage": 0,
                "total_products_outside_assortment": 0,
                "total_products_out_of_stock": 0,
                "share_percentage_growth": None,
                "products_outside_assortment_growth": None,
                "products_out_of_stock_growth": None
            }
            
        return jsonify({
            "success": True,
            "data": scorecard_data,
            "project_id": project_id,
            "country": countries_param
        })
        
    except Exception as e:
        print(f"Error fetching performance scorecards data: {str(e)}")
        traceback.print_exc()  # Print stack trace for better debugging
        return jsonify({
            "success": False,
            "error": f"Failed to fetch performance scorecards data: {str(e)}"
        }), 500



@product_discovery_performance_bp.route("/api/performance/categories", methods=["GET"])
@token_required
@project_access_required
def get_performance_categories(current_user, cloud_project_id=None):
    """
    Get categories with products in assortment for the Performance dashboard.
    Required query parameters:
    - country: The country code(s) to filter by (comma-separated for multiple countries)
    - project_id: The Firestore project ID to filter by
    """
    try:
        # Get parameters from request
        countries_param = request.args.get("country")
        
        # Validate country parameter
        if not countries_param:
            return jsonify({"error": "Country parameter is required"}), 400
            
        # Parse countries from comma-separated list
        countries = [country.strip() for country in countries_param.split(",")]
        if not countries:
            return jsonify({"error": "At least one valid country is required"}), 400
            
        # Get project ID - use the one from the decorator or from query param
        project_id = request.args.get("project_id", cloud_project_id)
        if not project_id:
            return jsonify({"error": "Project ID is required"}), 400
            
        # Create BigQuery client
        client = bigquery.Client()
        
        # Create an IN clause for the countries
        countries_clause = ", ".join([f'"{country}"' for country in countries])
        
        # Build the query to get categories with product counts across all selected countries
        query = f"""
        WITH category_data AS (
            SELECT DISTINCT
                category,
                country_code_bs,
                products_in_assortment
            FROM `s360-demand-sensing.project_performance.product_discovery_performance`
            WHERE LOWER(project_id) = LOWER("{project_id}")
            AND bestseller_date = (SELECT MAX(bestseller_date) FROM `s360-demand-sensing.project_performance.product_discovery_performance`)
            AND products_in_assortment > 0
            AND country_code_bs IN ({countries_clause})
        )
        
        SELECT
            category,
            SUM(products_in_assortment) AS products_in_assortment
        FROM category_data
        GROUP BY category
        ORDER BY products_in_assortment DESC
        """
        
        # Run the query
        query_job = client.query(query)
        results = query_job.result()
        
        # Process the results
        categories = []
        category_counts = {}
        
        for row in results:
            if row.category:
                categories.append(row.category)
                category_counts[row.category] = row.products_in_assortment
        
        return jsonify({
            "distinct_categories": categories,
            "category_counts": category_counts
        }), 200
        
    except Exception as e:
        logging.error(f"Error getting performance categories: {str(e)}")
        return jsonify({"error": f"Failed to get categories: {str(e)}"}), 500


@product_discovery_performance_bp.route("/api/performance/category-timeseries", methods=["GET"])
@token_required
@project_access_required
def get_category_timeseries(current_user, cloud_project_id=None):
    """
    Get category performance time series data for the Performance dashboard.
    Required query parameters:
    - country: The country code(s) to filter by (comma-separated for multiple countries)
    - project_id: The Firestore project ID to filter by
    Optional query parameters:
    - categories: Comma-separated list of categories to filter by
    
    Returns time series data showing share percentage over time for each country+category combination,
    with backfill information and merchant center products date.
    """
    try:
        # Get parameters from request
        countries_param = request.args.get("country")
        categories_param = request.args.get("categories")
        
        # Validate country parameter
        if not countries_param:
            return jsonify({"error": "Country parameter is required"}), 400
            
        # Parse countries from comma-separated list
        countries = [country.strip() for country in countries_param.split(",")]
        if not countries:
            return jsonify({"error": "At least one valid country is required"}), 400
            
        # Get project ID - use the one from the decorator or from query param
        project_id = request.args.get("project_id", cloud_project_id)
        if not project_id:
            return jsonify({"error": "Project ID is required"}), 400
            
        # Parse categories if provided
        categories = []
        if categories_param:
            categories = [cat.strip() for cat in categories_param.split(",")]
            
        # Create BigQuery client
        client = bigquery.Client()
        
        # Create an IN clause for the countries
        countries_clause = ", ".join([f"'{country}'" for country in countries])
        
        # Build the query to get time series data
        query = f"""
        WITH data AS (
            SELECT DISTINCT
                bestseller_date,
                country_code_bs,
                category,
                share_percentage,
                backfill,
                mc_products_date
            FROM `s360-demand-sensing.project_performance.product_discovery_performance`
            WHERE project_id = '{project_id}'
            AND country_code_bs IN ({countries_clause})
        ),
        
        category_data AS (
            SELECT 
                bestseller_date,
                country_code_bs,
                category,
                AVG(share_percentage) as share_percentage,
                MAX(backfill) AS backfill,
                MAX(mc_products_date) as mc_products_date
            FROM data
        """
        
        # Add category filter if provided
        if categories and len(categories) > 0:
            category_conditions = ", ".join([f"'{cat}'" for cat in categories])
            query += f"WHERE category IN ({category_conditions})"
            
        # Complete the query
        query += """
            GROUP BY bestseller_date, country_code_bs, category
        )
        SELECT 
            bestseller_date,
            country_code_bs,
            category,
            share_percentage,
            backfill,
            mc_products_date
        FROM category_data
        ORDER BY bestseller_date, country_code_bs, share_percentage DESC
        """
        
        # Run the query
        query_job = client.query(query)
        results = query_job.result()
        
        # Process the results
        timeseries_data = []
        
        for row in results:
            timeseries_data.append({
                "bestseller_date": row.bestseller_date.strftime("%Y-%m-%d") if row.bestseller_date else None,
                "country_code": row.country_code_bs,
                "category": row.category,
                "share_percentage": row.share_percentage,
                "backfill": row.backfill,
                "mc_products_date": row.mc_products_date.strftime("%Y-%m-%d") if row.mc_products_date else None
            })
            
        return jsonify({
            "success": True,
            "data": timeseries_data,
            "project_id": project_id,
            "country": countries_param
        })
        
    except Exception as e:
        print(f"Error fetching category time series data: {str(e)}")
        traceback.print_exc()  # Print stack trace for better debugging
        return jsonify({
            "success": False,
            "error": f"Failed to fetch category time series data: {str(e)}"
        }), 500


@product_discovery_performance_bp.route("/api/performance/rank-coverage", methods=["GET"])
@token_required
@project_access_required
def get_rank_coverage(current_user, cloud_project_id=None):
    """
    Get product rank coverage data for the Performance Deep Dive dashboard.
    Required query parameters:
    - country: The country code to filter by
    - project_id: The Firestore project ID to filter by
    Optional query parameters:
    - category: The specific category to filter by
    - date: The specific date to filter by (YYYY-MM-DD format)
    """
    try:
        # Get parameters from request
        country = request.args.get("country")
        category = request.args.get("category")
        date = request.args.get("date")
        
        # Validate country parameter
        if not country:
            return jsonify({"error": "Country parameter is required"}), 400
            
        # Get project ID - use the one from the decorator or from query param
        project_id = request.args.get("project_id", cloud_project_id)
        if not project_id:
            return jsonify({"error": "Project ID is required"}), 400
            
        # Create BigQuery client
        client = bigquery.Client()
        
        # Build the query to get rank coverage data
        query = f"""
        WITH performance_data AS (
            SELECT 
                bestseller_date,
                category,
                products_in_assortment,
                products_rank_below_10,
                products_rank_below_50,
                products_rank_below_100,
                products_rank_below_250,
                products_rank_below_500,
                products_rank_below_1000
            FROM `s360-demand-sensing.project_performance.product_discovery_performance`
            WHERE project_id = '{project_id}'
            AND country_code_bs = '{country}'
        """
        
        # Add category filter if provided
        if category:
            query += f"AND category = '{category}'"
            
        # Add date filter if provided
        if date:
            query += f"AND bestseller_date = '{date}'"
        else:
            # If no date specified, use the latest date
            query += """
            AND bestseller_date = (
                SELECT MAX(bestseller_date) 
                FROM `s360-demand-sensing.project_performance.product_discovery_performance`
                WHERE project_id = '{project_id}'
                AND country_code_bs = '{country}'
            )
            """
        
        # Close the CTE
        query += """
        )
        
        SELECT 
            bestseller_date,
            category,
            products_in_assortment,
            products_rank_below_10 AS top_10,
            products_rank_below_50 AS top_50,
            products_rank_below_100 AS top_100,
            products_rank_below_250 AS top_250,
            products_rank_below_500 AS top_500,
            products_rank_below_1000 AS top_1000,
            -- Calculate percentages
            SAFE_DIVIDE(products_rank_below_10, 10) AS top_10_pct,
            SAFE_DIVIDE(products_rank_below_50, 50) AS top_50_pct,
            SAFE_DIVIDE(products_rank_below_100, 100) AS top_100_pct,
            SAFE_DIVIDE(products_rank_below_250, 250) AS top_250_pct,
            SAFE_DIVIDE(products_rank_below_500, 500) AS top_500_pct,
            SAFE_DIVIDE(products_rank_below_1000, 1000) AS top_1000_pct
        FROM performance_data
        ORDER BY bestseller_date DESC, category
        """
        
        # If no specific category was provided, we'll get all categories, 
        # so limit to just the top ones by product count
        if not category:
            query = f"""
            WITH ranked_data AS ({query})
            SELECT *
            FROM ranked_data
            ORDER BY products_in_assortment DESC
            LIMIT 10
            """
        
        # Run the query
        query_job = client.query(query)
        results = query_job.result()
        
        # Process the results
        coverage_data = []
        
        for row in results:
            coverage_data.append({
                "bestseller_date": row.bestseller_date.strftime("%Y-%m-%d") if row.bestseller_date else None,
                "category": row.category,
                "products_in_assortment": row.products_in_assortment,
                # Rank count values
                "top_10": row.top_10,
                "top_50": row.top_50,
                "top_100": row.top_100,
                "top_250": row.top_250,
                "top_500": row.top_500,
                "top_1000": row.top_1000,
                # Percentage values
                "top_10_pct": row.top_10_pct,
                "top_50_pct": row.top_50_pct,
                "top_100_pct": row.top_100_pct,
                "top_250_pct": row.top_250_pct,
                "top_500_pct": row.top_500_pct,
                "top_1000_pct": row.top_1000_pct
            })
        
        # Also fetch all available dates for the date filter
        dates_query = f"""
        SELECT DISTINCT bestseller_date
        FROM `s360-demand-sensing.project_performance.product_discovery_performance`
        WHERE project_id = '{project_id}'
        AND country_code_bs = '{country}'
        """
        
        if category:
            dates_query += f"AND category = '{category}'"
            
        dates_query += """
        ORDER BY bestseller_date DESC
        LIMIT 24
        """
        
        dates_job = client.query(dates_query)
        dates_result = dates_job.result()
        
        available_dates = []
        for date_row in dates_result:
            available_dates.append(date_row.bestseller_date.strftime("%Y-%m-%d"))
            
        return jsonify({
            "success": True,
            "data": coverage_data,
            "available_dates": available_dates,
            "project_id": project_id,
            "country": country,
            "category": category,
            "date": date
        })
        
    except Exception as e:
        print(f"Error fetching rank coverage data: {str(e)}")
        traceback.print_exc()  # Print stack trace for better debugging
        return jsonify({
            "success": False,
            "error": f"Failed to fetch rank coverage data: {str(e)}"
        }), 500
