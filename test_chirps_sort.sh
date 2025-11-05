#!/bin/bash

# Test script to demonstrate the updated GET /api/chirps endpoint
# with optional sort query parameter

echo "Testing GET /api/chirps endpoint with sort parameter..."

# Test 1: Get all chirps with default sorting (asc)
echo "Test 1: GET /api/chirps (default ascending sort)"
curl -X GET "http://localhost:8080/api/chirps" \
  -H "Content-Type: application/json" \
  -w "\nHTTP Status: %{http_code}\n\n"

# Test 2: Get all chirps with explicit ascending sort
echo "Test 2: GET /api/chirps?sort=asc (explicit ascending sort)"
curl -X GET "http://localhost:8080/api/chirps?sort=asc" \
  -H "Content-Type: application/json" \
  -w "\nHTTP Status: %{http_code}\n\n"

# Test 3: Get all chirps with descending sort
echo "Test 3: GET /api/chirps?sort=desc (descending sort)"
curl -X GET "http://localhost:8080/api/chirps?sort=desc" \
  -H "Content-Type: application/json" \
  -w "\nHTTP Status: %{http_code}\n\n"

# Test 4: Get chirps for specific author with ascending sort
echo "Test 4: GET /api/chirps?author_id=<uuid>&sort=asc (filtered + ascending)"
curl -X GET "http://localhost:8080/api/chirps?author_id=190fa93d-3577-4238-809a-f0beaed02ad7&sort=asc" \
  -H "Content-Type: application/json" \
  -w "\nHTTP Status: %{http_code}\n\n"

# Test 5: Get chirps for specific author with descending sort
echo "Test 5: GET /api/chirps?author_id=<uuid>&sort=desc (filtered + descending)"
curl -X GET "http://localhost:8080/api/chirps?author_id=190fa93d-3577-4238-809a-f0beaed02ad7&sort=desc" \
  -H "Content-Type: application/json" \
  -w "\nHTTP Status: %{http_code}\n\n"

# Test 6: Invalid sort parameter (should return 400)
echo "Test 6: GET /api/chirps?sort=invalid (should return 400)"
curl -X GET "http://localhost:8080/api/chirps?sort=invalid" \
  -H "Content-Type: application/json" \
  -w "\nHTTP Status: %{http_code}\n\n"

echo "Done testing GET /api/chirps endpoint with sort parameter."
