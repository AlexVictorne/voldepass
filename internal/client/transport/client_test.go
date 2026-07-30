package transport_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexvictorne/voldepass/internal/client/transport"
	"github.com/alexvictorne/voldepass/internal/domain"
)

func newTestClient(t *testing.T, srv *httptest.Server) *transport.Client {
	t.Helper()
	c, err := transport.New(transport.Options{BaseURL: srv.URL, MaxRetries: 1})
	require.NoError(t, err)
	return c
}

func TestClient_Register_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/register", r.URL.Path)
		assert.Equal(t, domain.APIVersion, r.Header.Get("X-API-Version"))
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	err := c.Register(context.Background(), "alice", []byte("verifier"), domain.Profile{})
	assert.NoError(t, err)
}

func TestClient_Register_NotFoundMapsToDomainError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "already exists"})
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	err := c.Register(context.Background(), "alice", []byte("v"), domain.Profile{})
	assert.ErrorIs(t, err, domain.ErrConflict)
}

func TestClient_ChallengeAndLogin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/login/challenge":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"server_nonce":     "nonce123",
				"kdf_salt":         []byte("salt"),
				"kdf_params":       domain.DefaultKdfParams(),
				"wrapped_data_key": []byte("wrapped"),
			})
		case "/api/v1/login":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"access_token":  "access-tok",
				"refresh_token": "refresh-tok",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	ctx := context.Background()

	res, err := c.Challenge(ctx, "alice")
	require.NoError(t, err)
	assert.Equal(t, "nonce123", res.ServerNonce)
	assert.Equal(t, []byte("wrapped"), res.Profile.WrappedDataKey)

	err = c.Login(ctx, "alice", []byte("authmsg"))
	require.NoError(t, err)

	access, refresh := c.Tokens()
	assert.Equal(t, "access-tok", access)
	assert.Equal(t, "refresh-tok", refresh)
}

func TestClient_Refresh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			RefreshToken string `json:"refresh_token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		assert.Equal(t, "old-refresh", req.RefreshToken)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token":  "new-access",
			"refresh_token": "new-refresh",
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	c.SetTokens("old-access", "old-refresh")

	err := c.Refresh(context.Background())
	require.NoError(t, err)

	access, refresh := c.Tokens()
	assert.Equal(t, "new-access", access)
	assert.Equal(t, "new-refresh", refresh)
}

func TestClient_CertificatePinning_Valid(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cert := srv.Certificate()
	sum := sha256.Sum256(cert.Raw)
	fingerprint := hexEncode(sum[:])

	c, err := transport.New(transport.Options{BaseURL: srv.URL, MaxRetries: 0, PinnedFingerprint: fingerprint})
	require.NoError(t, err)

	err = c.Register(context.Background(), "alice", []byte("v"), domain.Profile{})
	assert.NoError(t, err)
}

func TestClient_CertificatePinning_Invalid(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Заведомо неверный отпечаток.
	wrongFingerprint := hexEncode(sha256.New().Sum(nil))

	c, err := transport.New(transport.Options{BaseURL: srv.URL, MaxRetries: 0, PinnedFingerprint: wrongFingerprint})
	require.NoError(t, err)

	err = c.Register(context.Background(), "alice", []byte("v"), domain.Profile{})
	assert.Error(t, err, "pinning mismatch must fail the TLS handshake")
}

func hexEncode(b []byte) string {
	const hextable = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hextable[v>>4]
		out[i*2+1] = hextable[v&0x0f]
	}
	return string(out)
}
