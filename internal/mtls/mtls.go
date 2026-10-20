package mtls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

// CAPair holds the parsed CA certificate, its private signing key, and a CertPool containing the CA.
type CAPair struct {
	Cert     *x509.Certificate
	Key      crypto.PrivateKey
	CertPool *x509.CertPool
}

// LoadCA loads a CA certificate and its private key from the specified pathList.
// The path can point to a single PEM file containing both the certificate and private key,
// or comma/colon-separated paths (e.g. "ca.crt,ca.key").
func LoadCA(pathList string) (*CAPair, error) {
	if pathList == "" {
		return nil, fmt.Errorf("CA path is empty")
	}

	var allPEM []byte
	for _, p := range strings.Split(pathList, ",") {
		p = strings.TrimSpace(p)
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("reading CA file %q: %w", p, err)
		}
		allPEM = append(allPEM, data...)
		allPEM = append(allPEM, '\n')
	}

	return parsePEMData(allPEM)
}

func parsePEMData(pemBytes []byte) (*CAPair, error) {
	var caCert *x509.Certificate
	var caKey crypto.PrivateKey
	caPool := x509.NewCertPool()

	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parsing certificate PEM: %w", err)
			}
			if caCert == nil {
				caCert = cert
			}
			caPool.AddCert(cert)
		} else if strings.Contains(block.Type, "PRIVATE KEY") {
			key, err := parsePrivateKey(block.Bytes, block.Type)
			if err != nil {
				return nil, fmt.Errorf("parsing private key PEM: %w", err)
			}
			if caKey == nil {
				caKey = key
			}
		}
	}

	if caCert == nil {
		return nil, fmt.Errorf("no CA certificate found")
	}
	if caKey == nil {
		return nil, fmt.Errorf("no CA private key found")
	}

	return &CAPair{
		Cert:     caCert,
		Key:      caKey,
		CertPool: caPool,
	}, nil
}

func parsePrivateKey(der []byte, blockType string) (crypto.PrivateKey, error) {
	switch blockType {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(der)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(der)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(der)
	default:
		if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
			return k, nil
		}
		if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
			return k, nil
		}
		if k, err := x509.ParseECPrivateKey(der); err == nil {
			return k, nil
		}
		return nil, fmt.Errorf("unsupported private key type %q", blockType)
	}
}

// GenerateTLSCertificate generates an ephemeral cert/key pair signed by the CA on the fly,
// valid for 1 year and returns it as a tls.Certificate including the certificate chain.
func (ca *CAPair) GenerateTLSCertificate(nodeID string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generating ephemeral private key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generating serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: nodeID,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, ca.Cert, &priv.PublicKey, ca.Key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("creating ephemeral certificate: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER, ca.Cert.Raw},
		PrivateKey:  priv,
	}, nil
}

// ServerTLSConfig creates a *tls.Config for the mTLS server.
// It requires peer client certificate authentication and validates that
// the client certificate is certified by this CA (hostname/IP is irrelevant).
func (ca *CAPair) ServerTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates:          []tls.Certificate{cert},
		ClientAuth:            tls.RequireAnyClientCert,
		ClientCAs:             ca.CertPool,
		VerifyPeerCertificate: ca.verifyPeerCertificate,
		MinVersion:            tls.VersionTLS12,
	}
}

// ClientTLSConfig creates a *tls.Config for peer client connections.
// It validates that the peer's certificate is certified by this CA (hostname/IP is irrelevant).
func (ca *CAPair) ClientTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates:          []tls.Certificate{cert},
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: ca.verifyPeerCertificate,
		MinVersion:            tls.VersionTLS12,
	}
}

// HTTPClient returns an *http.Client configured for mTLS communication with peers.
func (ca *CAPair) HTTPClient(cert tls.Certificate) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   ca.ClientTLSConfig(cert),
			DisableKeepAlives: false,
			MaxIdleConns:      10,
			IdleConnTimeout:   30 * time.Second,
		},
		Timeout: 10 * time.Second,
	}
}

// verifyPeerCertificate validates that a peer's presented certificate chain
// leads back to a trusted CA in caPool, ignoring hostname/IP.
func (ca *CAPair) verifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("peer presented no certificate")
	}

	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("failed to parse peer certificate: %w", err)
	}

	intermediates := x509.NewCertPool()
	for _, raw := range rawCerts[1:] {
		c, err := x509.ParseCertificate(raw)
		if err == nil {
			intermediates.AddCert(c)
		}
	}

	opts := x509.VerifyOptions{
		Roots:         ca.CertPool,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("peer certificate is not certified by trusted CA: %w", err)
	}

	return nil
}
