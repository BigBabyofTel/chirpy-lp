package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestHashPasswordAndVerifyPassword(t *testing.T) {
	password := "securepassword123"
	hashedPassword, err := HashPassword(password)
	require.NoError(t, err)
	require.NotEmpty(t, hashedPassword)

	isValid, err := VerifyPassword(password, hashedPassword)
	require.NoError(t, err)
	require.True(t, isValid)

	isValid, err = VerifyPassword("wrongpassword", hashedPassword)
	require.NoError(t, err)
	require.False(t, isValid)
}

func TestMakeJWTGeneratesValidToken(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "supersecretkey"
	expiresIn := time.Hour

	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	parsedToken, err := jwt.ParseWithClaims(token, &jwt.RegisteredClaims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(tokenSecret), nil
	})
	require.NoError(t, err)
	require.True(t, parsedToken.Valid)

	claims, ok := parsedToken.Claims.(*jwt.RegisteredClaims)
	require.True(t, ok)
	require.Equal(t, userID.String(), claims.Subject)
}

func TestValidateJWTReturnsUserIDOnValidToken(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "supersecretkey"
	expiresIn := time.Hour

	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	require.NoError(t, err)

	parsedUserID, err := ValidateJWT(token, tokenSecret)
	require.NoError(t, err)
	require.Equal(t, userID, parsedUserID)
}

func TestValidateJWTReturnsErrorOnInvalidToken(t *testing.T) {
	tokenSecret := "supersecretkey"
	invalidToken := "invalid.token.string"

	_, err := ValidateJWT(invalidToken, tokenSecret)
	require.Error(t, err)
}

func TestValidateJWTReturnsErrorOnExpiredToken(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "supersecretkey"
	expiresIn := -time.Hour // Token already expired

	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	require.NoError(t, err)

	_, err = ValidateJWT(token, tokenSecret)
	require.Error(t, err)
}

func GetBearerTokenExtractsTokenFromValidHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer abc.def.ghi")

	token, err := GetBearerToken(headers)
	require.NoError(t, err)
	require.Equal(t, "abc.def.ghi", token)
}

func GetBearerTokenIsCaseInsensitiveAndTrimsWhitespace(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "   bearer    xyz.123  ")

	token, err := GetBearerToken(headers)
	require.NoError(t, err)
	require.Equal(t, "xyz.123", token)
}

func GetBearerTokenReturnsErrorWhenHeaderMissing(t *testing.T) {
	headers := http.Header{}

	_, err := GetBearerToken(headers)
	require.Error(t, err)
}

func GetBearerTokenReturnsErrorForNonBearerScheme(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Basic abcdef")

	_, err := GetBearerToken(headers)
	require.Error(t, err)
}

func GetBearerTokenReturnsErrorForMalformedHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer")

	_, err := GetBearerToken(headers)
	require.Error(t, err)

	headers.Set("Authorization", "Bearer a b")
	_, err = GetBearerToken(headers)
	require.Error(t, err)
}

func TestGetAPIKeyValid(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey test-api-key-123")

	apiKey, err := GetAPIKey(headers)
	require.NoError(t, err)
	require.Equal(t, "test-api-key-123", apiKey)
}

func TestGetAPIKeyMissingHeader(t *testing.T) {
	headers := http.Header{}

	_, err := GetAPIKey(headers)
	require.Error(t, err)
	require.Contains(t, err.Error(), "authorization header missing")
}

func TestGetAPIKeyInvalidFormat(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer token-123")

	_, err := GetAPIKey(headers)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid authorization header format")
}

func TestGetAPIKeyEmptyKey(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey ")

	_, err := GetAPIKey(headers)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid authorization header format")
}
