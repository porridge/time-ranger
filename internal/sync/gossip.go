package sync

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"math/rand"
	"net/http"
	"slices"
	"time"
)

// SyncPayload is the wire format for gossip exchanges.
type SyncPayload struct {
	NodeID      string               `json:"node_id"`
	GeneratedAt time.Time            `json:"generated_at"`
	State       map[string]NodeState `json:"state"`
}

// GossipPeers performs a single gossip round: pick up to 4 random peers,
// POST our state, and merge their response.
func GossipPeers(client *http.Client, peers map[string]string, cluster *ClusterState, nodeID string) {
	const maxPerRun = 4
	if len(peers) == 0 {
		return
	}

	// Shuffle peer addresses randomly
	addrs := slices.Collect(maps.Values(peers))
	rand.Shuffle(len(addrs), func(i, j int) {
		addrs[i], addrs[j] = addrs[j], addrs[i]
	})

	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	scheme := "https"
	if tr, ok := client.Transport.(*http.Transport); !ok || tr.TLSClientConfig == nil {
		scheme = "http"
	}

	numSynced := 0
	for _, addr := range addrs {
		url := fmt.Sprintf("%s://%s/api/sync", scheme, addr)
		payload := SyncPayload{
			NodeID:      nodeID,
			GeneratedAt: time.Now().UTC(),
			State:       cluster.LocalState(),
		}
		data, err := json.Marshal(payload)
		if err != nil {
			continue
		}
		resp, err := client.Post(url, "application/json", bytes.NewReader(data))
		if err != nil {
			continue // peer unreachable
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			continue
		}
		var remotePayload SyncPayload
		if jsonErr := json.Unmarshal(body, &remotePayload); jsonErr != nil {
			continue
		}
		// Merge all nodes from the remote payload
		for remoteID, nodeState := range remotePayload.State {
			cluster.Merge(nodeID, remoteID, nodeState)
		}
		numSynced++
		if numSynced == maxPerRun {
			break
		}
	}
}
