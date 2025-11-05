#!/bin/bash

# Test script to verify the webhook endpoint works correctly
# This shows how the webhook should be called with proper authentication

POLKA_KEY="f271c81ff7084ee5b99a5091b42d486e"
USER_ID="190fa93d-3577-4238-809a-f0beaed02ad7"

echo "Testing Polka webhook endpoint..."

# Test 1: Valid request with correct API key
echo "Test 1: Valid request with user.upgraded event"
curl -X POST http://localhost:8080/api/polka/webhooks \
  -H "Authorization: ApiKey $POLKA_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"event\":\"user.upgraded\",\"data\":{\"user_id\":\"$USER_ID\"}}" \
  -w "\nHTTP Status: %{http_code}\n\n"

# Test 2: Request without Authorization header (should fail with 401)
echo "Test 2: Request without Authorization header (should fail)"
curl -X POST http://localhost:8080/api/polka/webhooks \
  -H "Content-Type: application/json" \
  -d "{\"event\":\"user.upgraded\",\"data\":{\"user_id\":\"$USER_ID\"}}" \
  -w "\nHTTP Status: %{http_code}\n\n"

# Test 3: Request with wrong API key (should fail with 401)
echo "Test 3: Request with wrong API key (should fail)"
curl -X POST http://localhost:8080/api/polka/webhooks \
  -H "Authorization: ApiKey wrong-key-123" \
  -H "Content-Type: application/json" \
  -d "{\"event\":\"user.upgraded\",\"data\":{\"user_id\":\"$USER_ID\"}}" \
  -w "\nHTTP Status: %{http_code}\n\n"

# Test 4: Valid request with ignored event
echo "Test 4: Valid request with ignored event"
curl -X POST http://localhost:8080/api/polka/webhooks \
  -H "Authorization: ApiKey $POLKA_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"event\":\"user.deleted\",\"data\":{\"user_id\":\"$USER_ID\"}}" \
  -w "\nHTTP Status: %{http_code}\n\n"

echo "Done testing webhook endpoint."
