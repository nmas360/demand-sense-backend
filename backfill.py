
#@app.route("/api/admin/category-assortment-backfill", methods=["GET"])
#def backfill_category_assortment(current_user=""):
#    """
#    Admin endpoint to backfill category assortment analysis for all historical dates
#    using current merchant center data.
#    """
#    try:
#        # Get all client projects from Firestore
#        projects_ref = firestore_client.collection('client_projects')
#        projects = list(projects_ref.stream())
#        
#        # Track results
#        backfill_results = {
#            "projects_processed": 0,
#            "merchant_centers_processed": 0,
#            "dates_processed": 0,
#            "total_rows_inserted": 0,
#            "errors": []
#        }
#        
#        log_rows_to_insert = []  # For BigQuery logging
#        analysis_timestamp = datetime.now()
#        
#        # Get all available dates from bestseller data
#        master_project_id = "s360-demand-sensing"
#        dates_query = f"""
#        SELECT DISTINCT date_month
#        FROM `{master_project_id}.ds_master_transformed_data.bestseller_monthly`
#        WHERE date_month IS NOT NULL
#        ORDER BY date_month DESC
#        """
#        
#        dates_job = bigquery_client.query(dates_query)
#        dates_results = list(dates_job.result())
#        available_dates = [row.date_month.isoformat() for row in dates_results]
#        
#        if not available_dates:
#            return jsonify({
#                "success": False,
#                "error": "No dates available in bestseller data"
#            }), 400
#            
#        backfill_results["available_dates"] = len(available_dates)
#        
#        # Create table if needed (same schema as in the main function)
#        try:
#            # First, make sure the dataset exists
#            dataset_ref = bigquery_client.dataset("web_app_logs", project=master_project_id)
#            try:
#                bigquery_client.get_dataset(dataset_ref)
#            except NotFound:
#                # Create the dataset if it doesn't exist
#                dataset = bigquery.Dataset(dataset_ref)
#                dataset.location = "EU"
#                bigquery_client.create_dataset(dataset)
#                
#            # Check if table exists, create if it doesn't
#            table_id = f"{master_project_id}.web_app_logs.category_assortment_analysis"
#            table_ref = bigquery_client.dataset("web_app_logs").table("category_assortment_analysis")
#            
#            try:
#                bigquery_client.get_table(table_ref)
#            except NotFound:
#                # Define schema
#                schema = [
#                    bigquery.SchemaField("timestamp", "TIMESTAMP", mode="REQUIRED"),
#                    bigquery.SchemaField("merchant_center_date", "DATE", mode="REQUIRED"),
#                    bigquery.SchemaField("bestseller_date", "DATE", mode="NULLABLE"),
#                    bigquery.SchemaField("project_id", "STRING", mode="REQUIRED"),
#                    bigquery.SchemaField("project_name", "STRING", mode="REQUIRED"),
#                    bigquery.SchemaField("cloud_project_id", "STRING", mode="REQUIRED"),
#                    bigquery.SchemaField("merchant_center_id", "STRING", mode="REQUIRED"),
#                    bigquery.SchemaField("country_code", "STRING", mode="REQUIRED"),
#                    bigquery.SchemaField("category", "STRING", mode="NULLABLE"),
#                    bigquery.SchemaField("is_top_category", "BOOLEAN", mode="NULLABLE"),
#                    bigquery.SchemaField("products_in_stock", "INTEGER", mode="NULLABLE"),
#                    bigquery.SchemaField("total_products", "INTEGER", mode="NULLABLE"),
#                    bigquery.SchemaField("share_percentage", "FLOAT", mode="NULLABLE")
#
#                ]
#                
#                table = bigquery.Table(table_ref, schema=schema)
#                table.time_partitioning = bigquery.TimePartitioning(
#                    type_=bigquery.TimePartitioningType.DAY,
#                    field="merchant_center_date"
#                )
#                table = bigquery_client.create_table(table)
#                print(f"Created table {table.project}.{table.dataset_id}.{table.table_id}")
#                
#        except Exception as table_error:
#            print(f"Error creating/checking BigQuery table: {str(table_error)}")
#            backfill_results["errors"].append(f"Table creation error: {str(table_error)}")
#            # Continue processing even if table creation fails
#        
#        # Process each project
#        for project_doc in projects:
#            project_data = project_doc.to_dict()
#            project_id = project_doc.id
#            cloud_project_id = project_data.get('cloudProjectId')
#            merchant_centers = project_data.get('merchantCenters', [])
#            
#            # Skip if no cloud project ID or merchant centers
#            if not cloud_project_id or not merchant_centers:
#                continue
#                
#            # Process each merchant center
#            for merchant_center in merchant_centers:
#                merchant_center_id = merchant_center.get('merchantCenterId')
#                country_code = merchant_center.get('code')
#                
#                if not merchant_center_id or not country_code:
#                    continue
#                
#                backfill_results["merchant_centers_processed"] += 1
#                mc_dates_processed = 0
#                
#                # Process each historical date
#                for bestseller_date in available_dates:
#                    try:
#                        # Use current products feed with historical bestseller data
#                        query = f"""
#                        WITH products AS (
#                          SELECT DISTINCT
#                            offer_id,
#                            product_id
#                          FROM `{cloud_project_id}.ds_raw_data.Products_{merchant_center_id}`
#                          WHERE _PARTITIONTIME = (SELECT MAX(_PARTITIONTIME) FROM `{cloud_project_id}.ds_raw_data.Products_{merchant_center_id}`)
#                          AND availability = 'in stock'
#                          AND channel = 'online'
#                        ),
#
#                        bestseller_main AS (
#                          SELECT DISTINCT
#                            category,
#                            entity_id
#                          FROM `{master_project_id}.ds_master_transformed_data.bestseller_monthly`
#                          WHERE country_code = '{country_code}'
#                          AND date_month = '{bestseller_date}'
#                        ),
#                        
#                        total_bestseller_counts AS (
#                          SELECT
#                            category,
#                            COUNT(DISTINCT entity_id) AS total_products
#                          FROM `{master_project_id}.ds_master_transformed_data.bestseller_monthly`
#                          WHERE country_code = '{country_code}'
#                          AND date_month = '{bestseller_date}'
#                          AND category IS NOT NULL
#                          GROUP BY category
#                        ),
#
#                        mapping AS (
#                          SELECT DISTINCT
#                            m.entity_id,
#                            m.product_id,
#                            bm.category
#                          FROM `{cloud_project_id}.ds_raw_data.BestSellersEntityProductMapping_{merchant_center_id}` AS m
#                          LEFT JOIN bestseller_main AS bm
#                          ON bm.entity_id = m.entity_id
#                        ),
#
#                        final AS (
#                          SELECT
#                            m.entity_id,
#                            m.category,
#                            p.* 
#                          FROM products AS p
#                          LEFT JOIN mapping AS m
#                          ON p.product_id = m.product_id
#                        ),
#                        
#                        category_counts AS (
#                          SELECT
#                            c.category AS level_1,
#                            COUNT(DISTINCT c.entity_id) AS products_in_stock,
#                            t.total_products,
#                            SAFE_DIVIDE(COUNT(DISTINCT c.entity_id), t.total_products) AS share_of_total
#                          FROM final c
#                          JOIN total_bestseller_counts t
#                          ON c.category = t.category
#                          WHERE c.category IS NOT NULL
#                          GROUP BY c.category, t.total_products
#                          ORDER BY products_in_stock DESC
#                        )
#                        
#                        SELECT 
#                            c.level_1,
#                            c.products_in_stock,
#                            c.total_products,
#                            c.share_of_total
#                        FROM category_counts AS c
#                        WHERE c.products_in_stock > 0
#                        ORDER BY c.products_in_stock DESC
#                        """
#                        
#                        # Execute the query
#                        query_job = bigquery_client.query(query)
#                        results_rows = list(query_job.result())
#                        
#                        # If there are categories with products in stock
#                        if results_rows:
#                            # Find top category
#                            top_category = results_rows[0].level_1
#                            
#                            # Process all categories for this date
#                            for row in results_rows:
#                                category = row.level_1
#                                products_count = row.products_in_stock
#                                total_products = row.total_products
#                                share_of_total = row.share_of_total
#                                share_percentage = round(share_of_total * 100, 2) if share_of_total else 0
#                                
#                                # Prepare data for BigQuery insert for this category
#                                bq_row = {
#                                    "timestamp": analysis_timestamp.strftime('%Y-%m-%d %H:%M:%S'),
#                                    "merchant_center_date": analysis_timestamp.strftime('%Y-%m-%d'),
#                                    "project_id": project_id,
#                                    "project_name": project_data.get('name', 'Unknown'),
#                                    "cloud_project_id": cloud_project_id,
#                                    "merchant_center_id": merchant_center_id,
#                                    "country_code": country_code,
#                                    "category": category,
#                                    "is_top_category": (category == top_category),
#                                    "products_in_stock": products_count,
#                                    "total_products": total_products,
#                                    "share_percentage": share_percentage,
#                                    "bestseller_date": bestseller_date
#                                }
#                                log_rows_to_insert.append(bq_row)
#                                
#                            mc_dates_processed += 1
#                        
#                    except Exception as date_error:
#                        error_msg = f"Error processing date {bestseller_date} for merchant center {merchant_center_id}: {str(date_error)}"
#                        print(error_msg)
#                        backfill_results["errors"].append(error_msg)
#                        continue
#                
#                backfill_results["dates_processed"] += mc_dates_processed
#            
#            backfill_results["projects_processed"] += 1
#            
#        # Insert data into BigQuery in batches to avoid exceeding limits
#        if log_rows_to_insert:
#            try:
#                table_id = f"{master_project_id}.web_app_logs.category_assortment_analysis"
#                
#                # Process in batches of 1000 rows
#                batch_size = 1000
#                for i in range(0, len(log_rows_to_insert), batch_size):
#                    batch = log_rows_to_insert[i:i + batch_size]
#                    errors = bigquery_client.insert_rows_json(table_id, batch)
#                    if errors:
#                        error_msg = f"Errors inserting batch {i//batch_size}: {errors}"
#                        print(error_msg)
#                        backfill_results["errors"].append(error_msg)
#                    else:
#                        print(f"Successfully inserted batch {i//batch_size} ({len(batch)} rows)")
#                        
#                backfill_results["total_rows_inserted"] = len(log_rows_to_insert)
#                
#            except Exception as insert_error:
#                error_msg = f"Error inserting data into BigQuery: {str(insert_error)}"
#                print(error_msg)
#                backfill_results["errors"].append(error_msg)
#        
#        # Return the backfill results
#        return jsonify({
#            "success": True,
#            "timestamp": analysis_timestamp.isoformat(),
#            "backfill_results": backfill_results
#        })
#        
#    except Exception as e:
#        print(f"Error during backfill operation: {str(e)}")
#        return jsonify({
#            "success": False,
#            "error": f"Failed during backfill operation: {str(e)}"
#        }), 500