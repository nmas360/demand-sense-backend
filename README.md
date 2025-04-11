# Demand Sensing Backend

This repository contains the backend code for the Demand Sensing application.

## Project Overview

The Demand Sensing backend provides API endpoints for demand forecasting and data analysis.

## Setup

1. Clone the repository:
   ```
   git clone https://github.com/nmas360/demand-sense-backend.git
   cd demand-sense-backend
   ```

2. Create a virtual environment and install dependencies:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. Set up environment variables:
   Create a `.env` file based on the provided template.

4. Run the application:
   ```
   python app.py
   ```

## Docker Support

The application can also be run using Docker:

```
docker build -t demand-sense-backend .
docker run -p 5000:5000 demand-sense-backend
``` 