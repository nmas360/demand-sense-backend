from flask import Blueprint
from utils.imports import *
from utils.config import *
from utils.decorators import *
from urllib.parse import quote

# Create the auth blueprint
trendspotting_brand_trends_bp = Blueprint('trendspotting_brand_trends', __name__)





@trendspotting_brand_trends_bp.route("/api/brand-trends", methods=["GET"])
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

@trendspotting_brand_trends_bp.route("/api/user/trendspotting-preferences", methods=["GET"])
@token_required
def get_trendspotting_preferences(current_user):
    """Get the filter preferences for the Brand Trends page"""
    try:
        # Get project_id from query parameters
        project_id = request.args.get('project_id')
        if not project_id:
            return jsonify({
                "success": False,
                "error": "Missing required parameter: project_id"
            }), 400
            
        # Get the user document from Firestore
        user_ref = firestore_client.collection('users').document(current_user)
        user_doc = user_ref.get()
        
        if not user_doc.exists:
            return jsonify({
                "success": False,
                "error": "User document not found"
            }), 404
        
        # Get the user data
        user_data = user_doc.to_dict()
        
        # Get project-specific trendspotting preferences
        # New structure: trendspotting_preferences is a dict with project_id as keys
        trendspotting_preferences = user_data.get('trendspotting_preferences', {})
        
        # Get project-specific preferences, or create defaults
        project_preferences = trendspotting_preferences.get(project_id, {})
        
        # If no preferences found for this project, use defaults
        # But first check if we have old-style preferences to migrate
        if not project_preferences:
            # Check for old-style preferences (not project-specific)
            if isinstance(trendspotting_preferences, dict) and any(key in trendspotting_preferences for key in ['selectedInspirationMarkets', 'selectedProjectMarkets', 'selectedInspirationCategories']):
                # Migrate old preferences to new project-specific format
                project_preferences = {
                    "selectedInspirationMarkets": trendspotting_preferences.get("selectedInspirationMarkets", ["US"]),
                    "selectedProjectMarkets": trendspotting_preferences.get("selectedProjectMarkets", []),
                    "selectedInspirationCategories": trendspotting_preferences.get("selectedInspirationCategories", [])
                }
                
                # Update user document with migrated preferences
                new_preferences = {project_id: project_preferences}
                user_ref.update({
                    "trendspotting_preferences": new_preferences,
                    "updated_at": firestore.SERVER_TIMESTAMP
                })
            else:
                # Default to US as inspiration market
                project_preferences = {
                    "selectedInspirationMarkets": ["US"],
                    "selectedProjectMarkets": [],  # Will be populated client-side with up to 3 available markets
                    "selectedInspirationCategories": []
                }
            
        return jsonify({
            "success": True,
            "data": project_preferences
        })
    except Exception as e:
        print(f"Error getting trendspotting preferences: {str(e)}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@trendspotting_brand_trends_bp.route("/api/user/trendspotting-preferences", methods=["POST"])
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
            
        # Get project_id from the request
        project_id = data.get('project_id')
        if not project_id:
            return jsonify({
                "success": False,
                "error": "Missing required field: project_id"
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
            
        # Get existing trendspotting preferences
        user_data = user_doc.to_dict()
        existing_preferences = user_data.get('trendspotting_preferences', {})
        
        # Check if existing preferences use the old format (not project-specific)
        if isinstance(existing_preferences, dict) and any(key in existing_preferences for key in ['selectedInspirationMarkets', 'selectedProjectMarkets', 'selectedInspirationCategories']):
            # Convert to new format
            existing_preferences = {}
        
        # Update preferences for this project only
        existing_preferences[project_id] = preferences
        
        # Update the trendspotting preferences
        user_ref.update({
            "trendspotting_preferences": existing_preferences,
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


@trendspotting_brand_trends_bp.route("/api/brand-trends/sparklines", methods=["GET"])
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
