# Security Scan Report
**Target:** https://httpbin.org
## Discovered URLs
- https://httpbin.org
## Endpoints Discovered
- **GET** `https://httpbin.org/v2/swagger.json`  (pattern: `/v2/swagger.json`)  _source: js_parse_
## Suspicious Responses
- **GET** https://httpbin.org/v2/swagger.json → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/v2/swagger.json?user_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/v2/swagger.json?account_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/v2/swagger.json?uid=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/v2/swagger.json?profile_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/v2/swagger.json?owner_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/v2/swagger.json?customer_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/v2/swagger.json?id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/v2/swagger.json?order_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/v2/swagger.json?document_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/v2/swagger.json?file_id=1 → 404  - Reason: Status 404 on API-like endpoint
## Possible Vulnerability Candidates
- (none)
## Scan Meta
- **pages_crawled:** 1
- **js_files_analyzed:** 3
- **endpoints_found:** 1
