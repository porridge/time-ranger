package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/porridge/time-ranger/internal/collector"
	"github.com/porridge/time-ranger/internal/discovery"
	"github.com/porridge/time-ranger/internal/mtls"
	"github.com/porridge/time-ranger/internal/sync"
	"github.com/porridge/time-ranger/internal/web"
)

var (
	cluster = sync.NewClusterState()
	peers   *discovery.PeerRegistry
)

type Config struct {
	GroupName string
	DataDir   string
	UIPort    int
	PeerPort  int
	CAPath    string
	NodeID    string
}

var cfg = &Config{}

func main() {
	// --- Load configuration ---
	cfg.GroupName = getEnv("TIME_RANGER_GROUP", "")
	cfg.DataDir = getEnv("TIME_RANGER_DATA", ".")
	cfg.UIPort = parseInt(getEnv("TIME_RANGER_UI_PORT", "4848"))
	cfg.PeerPort = parseInt(getEnv("TIME_RANGER_PEER_PORT", "4849"))
	cfg.CAPath = getEnv("TIME_RANGER_CA", "")
	var err error
	if cfg.NodeID, err = os.Hostname(); err != nil {
		log.Fatalf("Cannot obtain hostname: %v", err)
	}

	// Ensure data directory exists
	if err := os.MkdirAll(cfg.DataDir, 0755); err != nil {
		log.Fatalf("Cannot create data dir %s: %v", cfg.DataDir, err)
	}

	// --- Initialize collector ---
	coll := collector.New(cfg.GroupName, cfg.DataDir)

	// Populate local state into cluster immediately
	cluster.InitLocalNode(cfg.NodeID, coll)

	// --- Check peer mTLS configuration ---
	var caPair *mtls.CAPair
	var ephemeralCert tls.Certificate
	var gossipClient *http.Client
	peerEnabled := false

	if cfg.CAPath != "" {
		var err error
		caPair, err = mtls.LoadCA(cfg.CAPath)
		if err != nil {
			log.Fatalf("Failed to load CA cert/key from %q: %v", cfg.CAPath, err)
		}
		ephemeralCert, err = caPair.GenerateTLSCertificate(cfg.NodeID)
		if err != nil {
			log.Fatalf("Failed to generate ephemeral cert/key: %v", err)
		}
		gossipClient = caPair.HTTPClient(ephemeralCert)
		peerEnabled = true
		log.Printf("🔒 Peer syncing enabled with mTLS (port %d)", cfg.PeerPort)
	} else {
		log.Printf("ℹ️  Peer syncing disabled (port %d disabled by default; set TIME_RANGER_CA to enable)", cfg.PeerPort)
	}

	// --- Peer discovery & gossip ---
	peers = discovery.NewPeerRegistry()
	if peerEnabled {
		if err := discovery.StartMDNS(cfg.NodeID, cfg.PeerPort, peers); err != nil {
			log.Printf("[discovery] mDNS init warning: %v (continuing without discovery)", err)
		}

		// Periodic gossip sync every 30 seconds
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				sync.GossipPeers(gossipClient, peers.Get(), cluster, cfg.NodeID)
			}
		}()
	}

	// --- Periodic local collection every 5 minutes ---
	go func() {
		if err := coll.RunOnce(); err != nil {
			log.Printf("[collector] initial run error: %v", err)
		} else {
			cluster.UpdateLocalNode(cfg.NodeID, coll.GetLatestData())
		}
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			if err := coll.RunOnce(); err != nil {
				log.Printf("[collector] tick error: %v", err)
			} else {
				cluster.UpdateLocalNode(cfg.NodeID, coll.GetLatestData())
			}
		}
	}()

	// --- HTTP Handlers ---
	// UI Mux: serves API endpoints used by the web UI (summary and user detail) and web UI static assets
	uiMux := http.NewServeMux()
	uiMux.HandleFunc("/api/summary", handleSummary)
	uiMux.HandleFunc("/api/user", handleUserDetail)
	uiMux.Handle("/", http.FileServer(http.FS(web.StaticFS)))

	// Peer Mux: publicly accessible endpoint for syncs/gossip
	peerMux := http.NewServeMux()
	peerMux.HandleFunc("/api/sync", handleSync)

	uiAddr := fmt.Sprintf("127.0.0.1:%d", cfg.UIPort)
	uiServer := &http.Server{
		Addr:    uiAddr,
		Handler: uiMux,
	}

	uiLn4, err := net.Listen("tcp4", uiAddr)
	if err != nil {
		log.Fatalf("Cannot listen on %s: %v", uiAddr, err)
	}
	defer func() { _ = uiLn4.Close() }()

	uiLn6, _ := net.Listen("tcp6", fmt.Sprintf("[::1]:%d", cfg.UIPort))
	if uiLn6 != nil {
		defer func() { _ = uiLn6.Close() }()
		go func() {
			if err := uiServer.Serve(uiLn6); err != nil && err != http.ErrServerClosed {
				log.Printf("UI IPv6 server error: %v", err)
			}
		}()
	}

	var peerServer *http.Server
	if peerEnabled {
		peerServer = &http.Server{
			Addr:      fmt.Sprintf(":%d", cfg.PeerPort),
			Handler:   peerMux,
			TLSConfig: caPair.ServerTLSConfig(ephemeralCert),
		}

		go func() {
			log.Printf("🔒 Peer server listening on %s (mTLS)", peerServer.Addr)
			if err := peerServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Peer server failed: %v", err)
			}
		}()
	}

	// --- Graceful shutdown ---
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("Shutting down Time Ranger...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = uiServer.Shutdown(ctx)
		if peerServer != nil {
			_ = peerServer.Shutdown(ctx)
		}
		os.Exit(0)
	}()

	log.Printf("⏱️  Time Ranger UI running on %s (localhost only) | Group: %s | Node: %s", uiAddr, cfg.GroupName, cfg.NodeID)
	if err := uiServer.Serve(uiLn4); err != nil && err != http.ErrServerClosed {
		log.Fatalf("UI server failed: %v", err)
	}
}

type SummaryResponse struct {
	Group string                    `json:"group"`
	Users map[string]sync.UserTotal `json:"users"`
	Peers map[string]string         `json:"peers"`
}

func handleSummary(w http.ResponseWriter, r *http.Request) {
	users := cluster.AggregateToday()
	resp := SummaryResponse{
		Group: cfg.GroupName,
		Users: users,
		Peers: peers.Get(),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func handleSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var payload sync.SyncPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Merge all nodes from the remote payload
	for remoteID, nodeState := range payload.State {
		cluster.Merge(cfg.NodeID, remoteID, nodeState)
	}
	resp := sync.SyncPayload{
		NodeID:      cfg.NodeID,
		GeneratedAt: time.Now().UTC(),
		State:       cluster.LocalState(),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func handleUserDetail(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("name")
	if username == "" {
		http.Error(w, "Missing user name", http.StatusBadRequest)
		return
	}
	detail := cluster.GetUserWeekDetail(username)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(detail)
}

func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

func parseInt(s string) int {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	if err != nil {
		log.Fatalf("invalid int: %q", s)
	}
	return n
}
