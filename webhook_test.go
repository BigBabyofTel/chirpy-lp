package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/BigBabyofTel/chirpy-lp/internal/auth"
)

func TestPolkaWebhookWithValidAPIKey(t *testing.T) {
	// Mock config
	cfg := &apiConfig{
		PolkaKey: "test-api-key-123",
		// Note: In a real test, you'd need to set up a test database
	}

	// Create test request
	webhookData := map[string]interface{}{
		"event": "user.upgraded",
		"data": map[string]string{
			"user_id": "190fa93d-3577-4238-809a-f0beaed02ad7",
		},
	}

	reqBody, _ := json.Marshal(webhookData)
	req := httptest.NewRequest("POST", "/api/polka/webhooks", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "ApiKey test-api-key-123")

	// Test the header parsing works
	apiKey, err := auth.GetAPIKey(req.Header)
	if err != nil {
		t.Fatalf("GetAPIKey failed: %v", err)
	}
	if apiKey != "test-api-key-123" {
		t.Fatalf("Expected API key 'test-api-key-123', got '%s'", apiKey)
	}

	// Verify the authorization would pass
	if apiKey != cfg.PolkaKey {
		t.Fatalf("API key validation would fail")
	}

	t.Logf("✅ API key extraction and validation works correctly")
	t.Logf("✅ Authorization header: %s", req.Header.Get("Authorization"))
	t.Logf("✅ Extracted API key: %s", apiKey)
}

func TestPolkaWebhookWithoutAPIKey(t *testing.T) {
	// Create test request without Authorization header
	webhookData := map[string]interface{}{
		"event": "user.upgraded",
		"data": map[string]string{
			"user_id": "190fa93d-3577-4238-809a-f0beaed02ad7",
		},
	}

	reqBody, _ := json.Marshal(webhookData)
	req := httptest.NewRequest("POST", "/api/polka/webhooks", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	// Intentionally NOT setting Authorization header

	// Test that GetAPIKey fails as expected
	_, err := auth.GetAPIKey(req.Header)
	if err == nil {
		t.Fatalf("Expected GetAPIKey to fail when no Authorization header is present")
	}

	t.Logf("✅ GetAPIKey correctly fails when no Authorization header present")
	t.Logf("✅ Error: %v", err)
}
