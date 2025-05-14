from flask import Blueprint
from utils.imports import *
from utils.config import *
from utils.decorators import *
from urllib.parse import quote

# Create the auth blueprint
product_discovery_bp = Blueprint('product_discovery', __name__)



@product_discovery_bp.route("/api/popular_products", methods=["GET"])
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

@product_discovery_bp.route("/api/categories", methods=["GET"])
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

            elif country:
                country_filter_clause = f"AND country_code = '{country}'"

            
            # Determine which country code to use for products filtering - use original_code if available
            products_country_code = original_code if original_code else (country if country else "")
            
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

@product_discovery_bp.route("/api/complete_category_hierarchy", methods=["GET"])
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

@product_discovery_bp.route("/api/brands", methods=["GET"])
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

@product_discovery_bp.route("/api/countries", methods=["GET"])
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

@product_discovery_bp.route("/api/dates", methods=["GET"])
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


@product_discovery_bp.route("/api/products/<entity_id>/history", methods=["GET"])
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


@product_discovery_bp.route("/api/user/preferences", methods=["GET"])
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
    

    
@product_discovery_bp.route("/api/user/preferences", methods=["POST"])
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
    
  # Favorites API endpoints
@product_discovery_bp.route("/api/favorites", methods=["GET"])
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

@product_discovery_bp.route("/api/favorites", methods=["POST"])
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

@product_discovery_bp.route("/api/favorites/<entity_id>", methods=["DELETE"])
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
@product_discovery_bp.route("/api/lists", methods=["GET"])
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

@product_discovery_bp.route("/api/lists", methods=["POST"])
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

@product_discovery_bp.route("/api/lists/<list_id>", methods=["PUT"])
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

@product_discovery_bp.route("/api/lists/<list_id>", methods=["DELETE"])
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

@product_discovery_bp.route("/api/lists/<list_id>/items", methods=["GET"])
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

@product_discovery_bp.route("/api/lists/<list_id>/items/with-gtins", methods=["GET"])
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

@product_discovery_bp.route("/api/lists/<list_id>/items", methods=["POST"])
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

@product_discovery_bp.route("/api/lists/<list_id>/items/<entity_id>", methods=["DELETE"])
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

@product_discovery_bp.route("/api/lists/<list_id>/share", methods=["POST"])
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

@product_discovery_bp.route("/api/lists/<list_id>/unshare", methods=["POST"])
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
@product_discovery_bp.route("/api/projects/<project_id>/list-items", methods=["GET"])
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

@product_discovery_bp.route("/api/lists/<list_id>/export", methods=["GET"])
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

