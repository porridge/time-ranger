package mtls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func createTestCA(t *testing.T, keyType string) (certPEM []byte, keyPEM []byte) {
	t.Helper()
	var priv crypto.PrivateKey
	var pub crypto.PublicKey
	var err error

	switch keyType {
	case "rsa":
		rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		priv = rsaPriv
		pub = &rsaPriv.PublicKey
	case "ecdsa":
		ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		priv = ecPriv
		pub = &ecPriv.PublicKey
	case "ed25519":
		edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		priv = edPriv
		pub = edPub
	default:
		t.Fatalf("unknown keyType: %s", keyType)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	caTemplate := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "Test CA " + keyType,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, pub, priv)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	var keyBlock *pem.Block
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		keyBlock = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		require.NoError(t, err)
		keyBlock = &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	case ed25519.PrivateKey:
		b, err := x509.MarshalPKCS8PrivateKey(k)
		require.NoError(t, err)
		keyBlock = &pem.Block{Type: "PRIVATE KEY", Bytes: b}
	}
	keyPEM = pem.EncodeToMemory(keyBlock)

	return certPEM, keyPEM
}

func TestLoadCA(t *testing.T) {
	tempDir := t.TempDir()

	for _, keyType := range []string{"rsa", "ecdsa", "ed25519"} {
		t.Run("CombinedFile_"+keyType, func(t *testing.T) {
			certPEM, keyPEM := createTestCA(t, keyType)
			combinedPath := filepath.Join(tempDir, "ca_combined_"+keyType+".pem")
			require.NoError(t, os.WriteFile(combinedPath, append(certPEM, keyPEM...), 0600))

			ca, err := LoadCA(combinedPath)
			require.NoError(t, err)
			require.NotNil(t, ca.Cert)
			require.NotNil(t, ca.Key)
			require.NotNil(t, ca.CertPool)
		})
	}

	t.Run("SeparateFilesComma", func(t *testing.T) {
		certPEM, keyPEM := createTestCA(t, "ecdsa")
		certPath := filepath.Join(tempDir, "sep.crt")
		keyPath := filepath.Join(tempDir, "sep.key")
		require.NoError(t, os.WriteFile(certPath, certPEM, 0644))
		require.NoError(t, os.WriteFile(keyPath, keyPEM, 0600))

		ca, err := LoadCA(certPath + "," + keyPath)
		require.NoError(t, err)
		require.NotNil(t, ca.Cert)
		require.NotNil(t, ca.Key)
	})

	t.Run("MissingKeyError", func(t *testing.T) {
		certPEM, _ := createTestCA(t, "ecdsa")
		certPath := filepath.Join(tempDir, "no_key.pem")
		require.NoError(t, os.WriteFile(certPath, certPEM, 0644))

		_, err := LoadCA(certPath)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no CA private key found")
	})

	t.Run("MissingFile", func(t *testing.T) {
		_, err := LoadCA(filepath.Join(tempDir, "non_existent.pem"))
		require.Error(t, err)
	})
}

func TestGenerateTLSCertificate(t *testing.T) {
	certPEM, keyPEM := createTestCA(t, "ecdsa")
	tempFile := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(tempFile, append(certPEM, keyPEM...), 0600))

	ca, err := LoadCA(tempFile)
	require.NoError(t, err)

	tlsCert, err := ca.GenerateTLSCertificate("test-node-123")
	require.NoError(t, err)
	require.Len(t, tlsCert.Certificate, 2) // ephemeral cert + CA cert

	parsed, err := x509.ParseCertificate(tlsCert.Certificate[0])
	require.NoError(t, err)
	require.Equal(t, "test-node-123", parsed.Subject.CommonName)
	require.Contains(t, parsed.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	require.Contains(t, parsed.ExtKeyUsage, x509.ExtKeyUsageClientAuth)

	// Verify certificate is signed by the CA
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	_, err = parsed.Verify(x509.VerifyOptions{Roots: roots})
	require.NoError(t, err)
}

func TestMutualTLSCommunication(t *testing.T) {
	// Setup CA1
	certPEM1, keyPEM1 := createTestCA(t, "ecdsa")
	ca1File := filepath.Join(t.TempDir(), "ca1.pem")
	require.NoError(t, os.WriteFile(ca1File, append(certPEM1, keyPEM1...), 0600))
	ca1, err := LoadCA(ca1File)
	require.NoError(t, err)

	// Node 1 (Server): ephemeral cert with CN "server-node"
	serverCert, err := ca1.GenerateTLSCertificate("server-node")
	require.NoError(t, err)

	// Node 2 (Client): ephemeral cert with CN "client-node"
	clientCert, err := ca1.GenerateTLSCertificate("client-node")
	require.NoError(t, err)

	// Start server on random local port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/sync", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	serverTLS := ca1.ServerTLSConfig(serverCert)
	server := &http.Server{
		Handler:   mux,
		TLSConfig: serverTLS,
	}
	defer func() { _ = server.Close() }()

	go func() {
		_ = server.ServeTLS(listener, "", "")
	}()

	serverAddr := listener.Addr().String()

	t.Run("ValidPeerSuccess_HostnameIrrelevant", func(t *testing.T) {
		client := ca1.HTTPClient(clientCert)
		// Connect using IP 127.0.0.1 even though server's cert CN is "server-node"
		url := fmt.Sprintf("https://%s/api/sync", serverAddr)
		resp, err := client.Get(url)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, `{"status":"ok"}`, string(body))
	})

	// Setup CA2 (untrusted)
	certPEM2, keyPEM2 := createTestCA(t, "ecdsa")
	ca2File := filepath.Join(t.TempDir(), "ca2.pem")
	require.NoError(t, os.WriteFile(ca2File, append(certPEM2, keyPEM2...), 0600))
	ca2, err := LoadCA(ca2File)
	require.NoError(t, err)

	t.Run("UntrustedClientRejected", func(t *testing.T) {
		untrustedClientCert, err := ca2.GenerateTLSCertificate("evil-client")
		require.NoError(t, err)

		// Client has CA1 in its pool (trusts server) but presents cert signed by CA2
		clientTLS := ca1.ClientTLSConfig(untrustedClientCert)
		client := &http.Client{
			Transport: &http.Transport{TLSClientConfig: clientTLS},
			Timeout:   2 * time.Second,
		}

		url := fmt.Sprintf("https://%s/api/sync", serverAddr)
		_, err = client.Get(url)
		require.Error(t, err, "server should reject untrusted client certificate")
	})

	t.Run("UntrustedServerRejected", func(t *testing.T) {
		// Client configured with CA2 tries to connect to Server configured with CA1
		clientFromCA2 := ca2.HTTPClient(clientCert)
		clientFromCA2.Timeout = 2 * time.Second

		url := fmt.Sprintf("https://%s/api/sync", serverAddr)
		_, err := clientFromCA2.Get(url)
		require.Error(t, err, "client should reject server cert not signed by client's CA")
	})

	t.Run("ClientWithoutCertRejected", func(t *testing.T) {
		// Client connects with no client cert
		plainTLSClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: ca1.ClientTLSConfig(tlsCertZero()),
			},
			Timeout: 2 * time.Second,
		}
		// Clear certificates
		plainTLSClient.Transport.(*http.Transport).TLSClientConfig.Certificates = nil

		url := fmt.Sprintf("https://%s/api/sync", serverAddr)
		_, err := plainTLSClient.Get(url)
		require.Error(t, err, "server should require a client certificate")
	})
}

func tlsCertZero() tls.Certificate {
	return tls.Certificate{}
}
