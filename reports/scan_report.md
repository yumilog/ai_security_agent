# Security Scan Report
**Target:** https://httpbin.org
## Discovered URLs
- https://httpbin.org/forms/post
- https://httpbin.org
## Endpoints Discovered
- **GET** `https://httpbin.org/v2/swagger.json`  (pattern: `/v2/swagger.json`)  _source: js_parse_
- **GET** `https://httpbin.org/auth/actions.js`  (pattern: `/auth/actions.js`)  _source: js_parse_
- **GET** `https://httpbin.org/auth/index.js`  (pattern: `/auth/index.js`)  _source: js_parse_
- **GET** `https://httpbin.org/auth/reducers.js`  (pattern: `/auth/reducers.js`)  _source: js_parse_
- **GET** `https://httpbin.org/auth/selectors.js`  (pattern: `/auth/selectors.js`)  _source: js_parse_
- **GET** `https://httpbin.org/auth/spec-wrap-actions.js`  (pattern: `/auth/spec-wrap-actions.js`)  _source: js_parse_
## Suspicious Responses
- **GET** https://httpbin.org/v2/swagger.json → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/v2/swagger.json?user_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/v2/swagger.json?account_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/v2/swagger.json?uid=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/v2/swagger.json?profile_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/v2/swagger.json?owner_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/v2/swagger.json?customer_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/v2/swagger.json?id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/actions.js → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/actions.js?user_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/actions.js?account_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/actions.js?uid=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/actions.js?profile_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/actions.js?owner_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/actions.js?customer_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/actions.js?id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/index.js → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/index.js?user_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/index.js?account_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/index.js?uid=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/index.js?profile_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/index.js?owner_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/index.js?customer_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/index.js?id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/reducers.js → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/reducers.js?user_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/reducers.js?account_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/reducers.js?uid=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/reducers.js?profile_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/reducers.js?owner_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/reducers.js?customer_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/reducers.js?id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/selectors.js → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/selectors.js?user_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/selectors.js?account_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/selectors.js?uid=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/selectors.js?profile_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/selectors.js?owner_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/selectors.js?customer_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/selectors.js?id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/spec-wrap-actions.js → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/spec-wrap-actions.js?user_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/spec-wrap-actions.js?account_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/spec-wrap-actions.js?uid=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/spec-wrap-actions.js?profile_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/spec-wrap-actions.js?owner_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/spec-wrap-actions.js?customer_id=1 → 404  - Reason: Status 404 on API-like endpoint
- **GET** https://httpbin.org/auth/spec-wrap-actions.js?id=1 → 404  - Reason: Status 404 on API-like endpoint
## Possible Vulnerability Candidates
- (none)
## Scan Meta
- **pages_crawled:** 2
- **js_files_analyzed:** 3
- **endpoints_found:** 6
