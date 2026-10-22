# TrustVault – AI Prompt Log

## Entry 1: Setting Up the Flask Backend

- **Date:** 22 October 2026
- **Task:** Create the initial Flask application and test it.
- **Prompt I used:** I asked ChatGPT to guide me step by step in setting up the Flask backend in VS Code and writing my first automated test.
- **What I did:** I created the Flask application using an application factory, added a `/health` endpoint, and wrote a pytest test to check the response.
- **What I learned:** I learned how to create a basic Flask application, return JSON responses, and test an endpoint without starting a separate server.
- **Testing:** The health endpoint test passed, and I checked the endpoint in my browser.
- **My reflection:** Starting with a small feature helped me understand the project structure before moving on to the security-related features.
- **Commit:** 8bbebfc — add Flask application and health check test.

## Entry 2: Fixing Authentication Test Failures

- **Date:** 22 October 2026
- **Task:** Fix the failing authentication tests.
- **Prompt I used:** I shared my pytest output with ChatGPT and asked for help fixing the two failing tests.
- **Problem:** The protected profile endpoint returned a `302` redirect instead of the expected `401 Unauthorized` response for unauthenticated users.
- **What I changed:** I configured Flask-Login to return a JSON error response with HTTP status `401` when authentication is required.
- **What I learned:** I learned the difference between an HTTP redirect and an unauthorized response, and why JSON APIs should return appropriate HTTP status codes.
- **Testing:** Initially, four tests passed and two failed. Record the final result after rerunning pytest.
- **Commit:** dfd6bc4 - return unauthorized responses for protected routes