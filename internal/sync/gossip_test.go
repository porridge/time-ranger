package sync

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGossipPeers(t *testing.T) {
	clusterA := NewClusterState()
	clusterA.Nodes["node-a"] = NodeState{
		"2026-10-01": map[string]UserUsage{
			"alice": {Minutes: 120, LastUpdated: time.Now().UTC()},
		},
	}

	clusterB := NewClusterState()
	clusterB.Nodes["node-b"] = NodeState{
		"2026-10-01": map[string]UserUsage{
			"bob": {Minutes: 60, LastUpdated: time.Now().UTC()},
		},
	}

	// Server on node B
	serverB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/sync", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)

		var payload SyncPayload
		err := json.NewDecoder(r.Body).Decode(&payload)
		require.NoError(t, err)

		for remoteID, state := range payload.State {
			clusterB.Merge("node-b", remoteID, state)
		}

		resp := SyncPayload{
			NodeID:      "node-b",
			GeneratedAt: time.Now().UTC(),
			State:       clusterB.LocalState(),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer serverB.Close()

	// ServerB URL is "http://host:port", extract "host:port"
	peerAddr := serverB.Listener.Addr().String()
	peers := map[string]string{
		"node-b": peerAddr,
	}

	// Run GossipPeers from node A to node B
	GossipPeers(serverB.Client(), peers, clusterA, "node-a")

	// Both clusters should now have both nodes
	require.Contains(t, clusterA.Nodes, "node-b")
	require.Equal(t, 60.0, clusterA.Nodes["node-b"]["2026-10-01"]["bob"].Minutes)

	require.Contains(t, clusterB.Nodes, "node-a")
	require.Equal(t, 120.0, clusterB.Nodes["node-a"]["2026-10-01"]["alice"].Minutes)
}
