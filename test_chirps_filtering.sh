#!/bin/bash

# Test script to demonstrate the updated GET /api/chirps endpoint
# with optional author_id filtering

echo "Testing GET /api/chirps endpoint with author_id filtering..."

# Test 1: Get all chirps (no filtering)
echo "Test 1: GET /api/chirps (all chirps)"
curl -X GET "http://localhost:8080/api/chirps" \
  -H "Content-Type: application/json" \
  -w "\nHTTP Status: %{http_code}\n\n"

# Test 2: Get chirps for specific author
echo "Test 2: GET /api/chirps?author_id=<some-uuid> (filtered by author)"
curl -X GET "http://localhost:8080/api/chirps?author_id=190fa93d-3577-4238-809a-f0beaed02ad7" \
  -H "Content-Type: application/json" \
  -w "\nHTTP Status: %{http_code}\n\n"

# Test 3: Invalid author_id format (should return 400)
echo "Test 3: GET /api/chirps?author_id=invalid-uuid (should return 400)"
curl -X GET "http://localhost:8080/api/chirps?author_id=invalid-uuid" \
  -H "Content-Type: application/json" \
  -w "\nHTTP Status: %{http_code}\n\n"

echo "Done testing GET /api/chirps endpoint."
