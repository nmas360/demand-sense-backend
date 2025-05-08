
@app.route("/api/generate-dummy-data", methods=["GET"])
def generate_dummy_data():
    """
    Creates dummy datasets in BigQuery with unique random product IDs for each specified country.
    Each table will be created at demandsense-demo.ds_raw_data.Products_{country}
    and will be partitioned by _PARTITIONTIME with DAY granularity and 60-day expiry.
    """
    print("Starting dummy data generation process...")
    try:
        # Parameters (can be changed or made into request parameters)
        country_codes = ["BE","CH","DE","GR","ES","GB","CA","NO","IT","DK","FI","FR","PL","PT","IE","US","NL","SE","AT", "AU"]  # Uppercase country codes
        min_product_id = 1
        max_product_id = 4075266
        dataset_size = 650000  # Number of records per country
        
        # Validate that dataset size doesn't exceed possible range
        valid_range_size = max_product_id - min_product_id + 1
        if dataset_size > valid_range_size:
            return jsonify({
                "success": False,
                "error": f"Dataset size ({dataset_size}) exceeds available ID range ({valid_range_size})"
            }), 400
            
        print(f"Generating data for countries: {country_codes}")
        print(f"Product ID range: {min_product_id} to {max_product_id}")
        print(f"Dataset size per country: {dataset_size}")
        
        # Define the dataset base name
        dataset_base = "demandsense-demo.ds_raw_data.Products"
        
        results = {}
        
        # Process each country
        for country_code in country_codes:
            # Create table ID with lowercase country code
            table_id = f"{dataset_base}_{country_code.lower()}"
            print(f"\nProcessing country: {country_code}")
            print(f"Target table: {table_id}")
            
            # Create the table schema
            schema = [
                bigquery.SchemaField("Offer_id", "INTEGER"),
                bigquery.SchemaField("Product_id", "STRING"),
                bigquery.SchemaField("product_data_timestamp", "TIMESTAMP"),
                bigquery.SchemaField("Availability", "STRING"),
                bigquery.SchemaField("Channel", "STRING"),
                bigquery.SchemaField("feed_label", "STRING"),
                bigquery.SchemaField("target_country", "STRING"),
            ]
            print(f"Schema defined with {len(schema)} fields")
            
            # Create the table with time partitioning
            table = bigquery.Table(table_id, schema=schema)
            table.time_partitioning = bigquery.TimePartitioning(
                type_=bigquery.TimePartitioningType.DAY,
                expiration_ms=60 * 24 * 60 * 60 * 1000  # 60 days in milliseconds
            )
            # Make partition filter not required
            table.require_partition_filter = False
            print("Table configured with time partitioning by DAY on _PARTITIONTIME with 60-day expiry")
            
            # Check if table exists, if not create it
            print("Checking if table already exists...")
            try:
                bigquery_client.get_table(table_id)
                print(f"Table {table_id} exists, deleting it first...")
                # Table exists, delete it first
                bigquery_client.delete_table(table_id)
                print(f"Table {table_id} deleted successfully.")
                logging.info(f"Table {table_id} deleted.")
            except NotFound:
                # Table doesn't exist, continue
                print(f"Table {table_id} does not exist yet, will create new.")
                pass
            
            # Create the table
            print("Creating the table...")
            table = bigquery_client.create_table(table)
            print(f"Table created successfully: {table.table_id}")
            logging.info(f"Created table {table_id}")
            
            # Generate a random set of unique product IDs within range
            print(f"Generating {dataset_size} unique random product IDs between {min_product_id} and {max_product_id}...")
            # Use random.sample to get unique random IDs within range
            product_ids = random.sample(range(min_product_id, max_product_id + 1), dataset_size)
            
            # Function to generate a batch of records
            def generate_batch(start_index, batch_size, current_timestamp, country_code, product_ids):
                batch = []
                for i in range(start_index, min(start_index + batch_size, dataset_size)):
                    # Use the product ID as both offer_id and product_id
                    pid = product_ids[i]
                    record = {
                        "Offer_id": pid,
                        "Product_id": str(pid),
                        "product_data_timestamp": current_timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                        "Availability": "in stock" if np.random.random() < 0.8 else "out of stock",
                        "Channel": "online",
                        "feed_label": country_code,  # Use uppercase country code in data
                        "target_country": country_code  # Use uppercase country code in data
                    }
                    batch.append(record)
                return batch
                
            # Function to insert a batch of records
            def insert_batch(batch_index, batch_data, current_timestamp, table_id):
                batch_num = batch_index + 1
                try:
                    print(f"Inserting batch {batch_num} with {len(batch_data)} records...")
                    
                    # Use a partition decorator with the current date to ensure data goes into today's partition
                    partition_date = current_timestamp.strftime("%Y%m%d")
                    partitioned_table_id = f"{table_id}${partition_date}"
                    print(f"Using partitioned table ID: {partitioned_table_id}")
                    
                    errors = bigquery_client.insert_rows_json(partitioned_table_id, batch_data)
                    if errors:
                        print(f"ERRORS in batch {batch_num}: {errors}")
                        return False, errors
                    print(f"Batch {batch_num} inserted successfully")
                    return True, None
                except Exception as e:
                    print(f"EXCEPTION in batch {batch_num}: {str(e)}")
                    return False, str(e)
            
            # Generate and insert the dummy data
            current_timestamp = datetime.now()
            print(f"Using timestamp: {current_timestamp} for all records")
            
            # Split data generation into batches for concurrent processing
            batch_size = 5000
            num_batches = (dataset_size + batch_size - 1) // batch_size  # Ceiling division
            print(f"Splitting generation into {num_batches} batches of approximately {batch_size} records each")
            
            # First generate all batches
            all_batches = []
            for batch_idx in range(num_batches):
                start_index = batch_idx * batch_size
                
                batch_data = generate_batch(start_index, batch_size, current_timestamp, country_code, product_ids)
                all_batches.append((batch_data, table_id))
                
                # Print progress
                records_so_far = min((batch_idx + 1) * batch_size, dataset_size)
                print(f"Generated {records_so_far} records so far...")
                
            # Use ThreadPoolExecutor to insert batches concurrently
            print("Starting concurrent batch insertions with ThreadPoolExecutor...")
            batch_results = []
            with ThreadPoolExecutor(max_workers=min(10, num_batches)) as executor:
                futures = {executor.submit(insert_batch, i, batch_data, current_timestamp, table_id): i 
                          for i, (batch_data, table_id) in enumerate(all_batches)}
                for future in futures:
                    success, error = future.result()
                    batch_results.append((futures[future], success, error))
            
            # Check results
            failures = [r for r in batch_results if not r[1]]
            if failures:
                print(f"WARNING: {len(failures)} batches failed to insert")
                results[country_code] = {
                    "success": False,
                    "message": f"Some batches failed to insert. {len(failures)} failures out of {num_batches} batches.",
                    "failures": [{"batch": f[0], "error": f[2]} for f in failures],
                    "table_id": table_id
                }
            else:
                print(f"All {dataset_size} records inserted successfully using {num_batches} concurrent batches")
                results[country_code] = {
                    "success": True,
                    "message": f"Successfully created dummy dataset with {dataset_size} records",
                    "table_id": table_id
                }
        
        # Return overall results
        overall_success = all(country_result["success"] for country_result in results.values())
        return jsonify({
            "success": overall_success,
            "message": f"Processed {len(country_codes)} countries",
            "country_results": results
        })
        
    except Exception as e:
        print(f"ERROR generating dummy data: {str(e)}")
        print(f"Error traceback: {traceback.format_exc()}")
        logging.error(f"Error generating dummy data: {str(e)}")
        return jsonify({"error": f"Error generating dummy data: {str(e)}"}), 500

@app.route("/api/generate-mapping-tables", methods=["GET"])
def generate_mapping_tables():
    """
    Creates BestSellersEntityProductMapping tables for multiple countries.
    Each table will map entity_ids to product_ids from bestseller_monthly data.
    """
    print("Starting mapping tables generation process...")
    try:
        # Use the same country codes as in the dummy data generation
        country_codes = ["BE","CH","DE","GR","ES","GB","CA","NO","IT","DK","FI","FR","PL","PT","IE","US","NL","SE","AT","AU"]
        
        results = {}
        
        # Process each country
        for country_code in country_codes:
            country_lower = country_code.lower()
            print(f"\nProcessing country: {country_code}")
            
            try:
                # Create and populate table for this country
                table_id = f"demandsense-demo.ds_raw_data.BestSellersEntityProductMapping_{country_lower}"
                
                # SQL to create the table
                create_table_sql = f"""
                CREATE OR REPLACE TABLE
                  `{table_id}`
                (
                  entity_id  STRING,
                  product_id STRING
                )
                PARTITION BY _PARTITIONDATE
                OPTIONS (
                  require_partition_filter = FALSE,
                  partition_expiration_days = NULL
                );
                """
                
                # SQL to populate the table
                populate_table_sql = f"""
                INSERT INTO
                  `{table_id}`
                  (entity_id, product_id)
                WITH distinct_ids AS (
                  SELECT DISTINCT entity_id
                  FROM `s360-demand-sensing.ds_master_transformed_data.bestseller_monthly`
                )
                SELECT
                  CAST(entity_id AS STRING)                                   AS entity_id,
                  CAST(ROW_NUMBER() OVER (ORDER BY entity_id) AS STRING)      AS product_id
                FROM distinct_ids;
                """
                
                # Execute SQL to create the table
                print(f"Creating table for {country_code}...")
                create_job = bigquery_client.query(create_table_sql)
                create_job.result()  # Wait for the job to complete
                
                # Execute SQL to populate the table
                print(f"Populating table for {country_code}...")
                populate_job = bigquery_client.query(populate_table_sql)
                populate_job.result()  # Wait for the job to complete
                
                print(f"Successfully created and populated mapping table for {country_code}")
                results[country_code] = {
                    "success": True,
                    "message": f"Successfully created and populated mapping table for {country_code}",
                    "table_id": table_id
                }
                
            except Exception as e:
                error_message = str(e)
                print(f"ERROR processing {country_code}: {error_message}")
                results[country_code] = {
                    "success": False,
                    "message": f"Failed to create mapping table for {country_code}",
                    "error": error_message,
                    "table_id": table_id if 'table_id' in locals() else f"demandsense-demo.ds_raw_data.BestSellersEntityProductMapping_{country_lower}"
                }
                # Continue with the next country
        
        # Calculate overall stats
        success_count = sum(1 for result in results.values() if result["success"])
        failure_count = len(results) - success_count
        
        return jsonify({
            "success": failure_count == 0,
            "message": f"Processed {len(country_codes)} countries: {success_count} succeeded, {failure_count} failed",
            "country_results": results
        })
        
    except Exception as e:
        print(f"ERROR in generate_mapping_tables: {str(e)}")
        print(f"Error traceback: {traceback.format_exc()}")
        logging.error(f"Error generating mapping tables: {str(e)}")
        return jsonify({"error": f"Error generating mapping tables: {str(e)}"}), 500
