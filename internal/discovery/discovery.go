package discovery

import (
	"fmt"
	"maps"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/mdns"
)

// PeerRegistry holds known peers: node_id -> "ip:port".
type PeerRegistry struct {
	mutex sync.RWMutex
	peers map[string]string
}

func (p *PeerRegistry) Get() map[string]string {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	mapCopy := make(map[string]string, len(p.peers))
	maps.Copy(mapCopy, p.peers)
	return mapCopy
}

// NewPeerRegistry creates an empty registry.
func NewPeerRegistry() *PeerRegistry {
	return &PeerRegistry{peers: make(map[string]string)}
}

// StartMDNS advertises this node as a _time-ranger._tcp service and
// periodically discovers other peers via mDNS queries.
func StartMDNS(nodeID string, port int, reg *PeerRegistry) error {
	addr, err := getOutboundIP()
	if err != nil {
		addr = net.ParseIP("127.0.0.1")
	}

	service, err := mdns.NewMDNSService(
		nodeID,
		"_time-ranger._tcp",
		"",
		"",
		port,
		[]net.IP{addr},
		[]string{fmt.Sprintf("node=%s", nodeID)},
	)
	if err != nil {
		return fmt.Errorf("new mDNS service: %w", err)
	}

	server, err := mdns.NewServer(&mdns.Config{Zone: service})
	if err != nil {
		return fmt.Errorf("mDNS server: %w", err)
	}
	_ = server

	// Periodic query loop
	go func() {
		for {
			entriesCh := make(chan *mdns.ServiceEntry, 32)
			done := make(chan struct{})
			go func() {
				for entry := range entriesCh {
					if entry.Name == nodeID {
						continue
					}
					if entry.Port != port {
						// Crude workaround for https://github.com/hashicorp/mdns/issues/96
						continue
					}
					addr := fmt.Sprintf("%s:%d", entry.AddrV4, entry.Port)
					reg.mutex.Lock()
					reg.peers[entry.Name] = addr
					reg.mutex.Unlock()
				}
				close(done)
			}()

			_ = mdns.Query(&mdns.QueryParam{
				Service: "_time-ranger._tcp",
				Domain:  "local",
				Timeout: 5 * time.Second,
				Entries: entriesCh,
			})
			<-done

			time.Sleep(30 * time.Second)
		}
	}()

	return nil
}

func getOutboundIP() (net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	local := conn.LocalAddr().(*net.UDPAddr)
	return local.IP, nil
}
