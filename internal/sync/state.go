package sync

import (
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/porridge/time-ranger/internal/collector"
)

// UserUsage holds per-user screen time data for a single date on a single node.
type UserUsage struct {
	Minutes     float64   `json:"minutes"`
	LastUpdated time.Time `json:"last_updated"`
}

// NodeState is the per-node state map: date -> username -> UserUsage.
type NodeState map[string]map[string]UserUsage

// ClusterState is the global in-memory store: node_id -> NodeState.
type ClusterState struct {
	mu    sync.RWMutex
	Nodes map[string]NodeState
}

// NewClusterState creates an empty cluster state.
func NewClusterState() *ClusterState {
	return &ClusterState{Nodes: make(map[string]NodeState)}
}

// InitLocalNode initializes the local node state from collector files.
func (cs *ClusterState) InitLocalNode(nodeID string, coll *collector.Collector) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	raw := coll.GetLatestData()
	nodeState := make(NodeState)
	now := time.Now().UTC()

	for date, userMap := range raw {
		if _, ok := nodeState[date]; !ok {
			nodeState[date] = make(map[string]UserUsage)
		}
		for user, mins := range userMap {
			nodeState[date][user] = UserUsage{
				Minutes:     mins,
				LastUpdated: now,
			}
		}
	}
	cs.Nodes[nodeID] = nodeState
}

// UpdateLocalNode updates the local node state with fresh collected values,
// keeping local data authoritative.
func (cs *ClusterState) UpdateLocalNode(nodeID string, raw map[string]map[string]float64) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	nodeState, exists := cs.Nodes[nodeID]
	if !exists {
		nodeState = make(NodeState)
		cs.Nodes[nodeID] = nodeState
	}

	now := time.Now().UTC()
	for date, userMap := range raw {
		if _, ok := nodeState[date]; !ok {
			nodeState[date] = make(map[string]UserUsage)
		}
		for user, mins := range userMap {
			nodeState[date][user] = UserUsage{
				Minutes:     mins,
				LastUpdated: now,
			}
		}
	}
}

// To prevent XSS/FS walk/DoS:
var userRe regexp.Regexp = *regexp.MustCompile("^[a-zA-Z0-9_-]+$")
var nodeRe regexp.Regexp = *regexp.MustCompile("^[a-zA-Z0-9_.-]+$")

const maxNodes = 128
const maxDates = 100 * 365
const maxUsers = 128

// Merge integrates remote state into the cluster. The local node remains authoritative
// for its own records; remote data is cached for remote nodes.
func (cs *ClusterState) Merge(localNodeID string, remoteNodeID string, remoteState NodeState) {
	// Do not allow remote nodes to overwrite our own local node data
	if remoteNodeID == localNodeID {
		return
	}
	if !nodeRe.MatchString(remoteNodeID) {
		return
	}

	cs.mu.Lock()
	defer cs.mu.Unlock()

	local, exists := cs.Nodes[remoteNodeID]
	if !exists {
		if len(cs.Nodes) >= maxNodes {
			// Prevent DoS
			return
		}
		if len(remoteState) > maxDates {
			// Prevent DoS
			return
		}
		for _, userMap := range remoteState {
			if len(userMap) > maxUsers {
				// Prevent DoS
				break
			}
		}
		cs.Nodes[remoteNodeID] = remoteState
		return
	}

	for date, userMap := range remoteState {
		if len(userMap) > maxUsers {
			// Prevent DoS
			break
		}
		if _, ok := local[date]; !ok {
			local[date] = make(map[string]UserUsage)
		}
		for user, usage := range userMap {
			cur, ok := local[date][user]
			if !ok && len(local[date]) >= 128 {
				// Prevent DoS
				continue
			}
			if !userRe.MatchString(user) {
				// Ignore unsafe usernames
				continue
			}
			if !ok || usage.LastUpdated.After(cur.LastUpdated) {
				local[date][user] = usage
			}
		}
	}
}
func (cs *ClusterState) LocalState() map[string]NodeState {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.Nodes // note: shallow copy; callers should not mutate
}

// UserTotal aggregates a single user's time across all nodes.
type UserTotal struct {
	TodayMinutes    float64   `json:"today_minutes"`
	WeekMinutes     float64   `json:"week_minutes"`
	LastWeekMinutes float64   `json:"last_week_minutes"`
	Sources         int       `json:"sources"`
	LastSeen        time.Time `json:"last_seen"`
}

// UserWeekDetail holds the day x machine breakdown for current week and last week.
type UserWeekDetail struct {
	User           string                        `json:"user"`
	Days           []string                      `json:"days"`     // current week days
	Machines       []string                      `json:"machines"` // list of all cluster node IDs
	Grid           map[string]map[string]float64 `json:"grid"`     // current week: day -> machine -> minutes
	Totals         map[string]float64            `json:"totals"`   // current week: day -> total minutes
	LastWeekDays   []string                      `json:"last_week_days"`
	LastWeekGrid   map[string]map[string]float64 `json:"last_week_grid"`
	LastWeekTotals map[string]float64            `json:"last_week_totals"`
}

// GetUserWeekDetail builds a day x machine matrix for a specific user for current week and last week.
func (cs *ClusterState) GetUserWeekDetail(username string) UserWeekDetail {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	now := time.Now()
	weekday := int(now.Weekday())
	if weekday == 0 {
		weekday = 7
	}
	thisMondayDate := now.AddDate(0, 0, -(weekday - 1))

	var currentDays []string
	for i := range 7 {
		d := thisMondayDate.AddDate(0, 0, i)
		if d.After(now) && d.Format("2006-01-02") != now.Format("2006-01-02") {
			// Don't include future days in the current week
			break
		}
		currentDays = append(currentDays, d.Format("2006-01-02"))
	}

	lastMondayDate := thisMondayDate.AddDate(0, 0, -7)
	var lastWeekDays []string
	for i := range 7 {
		d := lastMondayDate.AddDate(0, 0, i)
		lastWeekDays = append(lastWeekDays, d.Format("2006-01-02"))
	}

	// Discover all machines in cluster (sorted for consistency)
	machineMap := make(map[string]bool)
	for nodeID := range cs.Nodes {
		machineMap[nodeID] = true
	}
	var machines []string
	for m := range machineMap {
		machines = append(machines, m)
	}
	slices.Sort(machines)

	grid := make(map[string]map[string]float64)
	totals := make(map[string]float64)

	for _, day := range currentDays {
		grid[day] = make(map[string]float64)
		for _, m := range machines {
			grid[day][m] = 0
			if nodeState, ok := cs.Nodes[m]; ok {
				if dayMap, ok := nodeState[day]; ok {
					if usage, ok := dayMap[username]; ok {
						grid[day][m] = usage.Minutes
						totals[day] += usage.Minutes
					}
				}
			}
		}
	}

	lastGrid := make(map[string]map[string]float64)
	lastTotals := make(map[string]float64)

	for _, day := range lastWeekDays {
		lastGrid[day] = make(map[string]float64)
		for _, m := range machines {
			lastGrid[day][m] = 0
			if nodeState, ok := cs.Nodes[m]; ok {
				if dayMap, ok := nodeState[day]; ok {
					if usage, ok := dayMap[username]; ok {
						lastGrid[day][m] = usage.Minutes
						lastTotals[day] += usage.Minutes
					}
				}
			}
		}
	}

	return UserWeekDetail{
		User:           username,
		Days:           currentDays,
		Machines:       machines,
		Grid:           grid,
		Totals:         totals,
		LastWeekDays:   lastWeekDays,
		LastWeekGrid:   lastGrid,
		LastWeekTotals: lastTotals,
	}
}

// AggregateToday computes today's, this week's (starting Monday), and last week's total minutes per user across all nodes.
func (cs *ClusterState) AggregateToday() map[string]UserTotal {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	now := time.Now()
	today := now.Format("2006-01-02")

	// Calculate Monday of the current week
	// Go's Weekday: Sunday = 0, Monday = 1, ..., Saturday = 6
	weekday := int(now.Weekday())
	if weekday == 0 {
		weekday = 7
	}
	thisMondayDate := now.AddDate(0, 0, -(weekday - 1))
	thisMonday := time.Date(thisMondayDate.Year(), thisMondayDate.Month(), thisMondayDate.Day(), 0, 0, 0, 0, thisMondayDate.Location())
	lastMonday := thisMonday.AddDate(0, 0, -7)

	result := make(map[string]UserTotal)

	// Collect unique users and aggregate by date ranges
	for _, nodeState := range cs.Nodes {
		for dateStr, dayMap := range nodeState {
			parsedDate, err := time.Parse("2006-01-02", dateStr)
			if err != nil {
				continue
			}

			isToday := (dateStr == today)
			isThisWeek := !parsedDate.Before(thisMonday) && !parsedDate.After(now)
			isLastWeek := !parsedDate.Before(lastMonday) && parsedDate.Before(thisMonday)

			for user, usage := range dayMap {
				total := result[user]
				if isToday {
					total.TodayMinutes += usage.Minutes
					total.Sources++
				}
				if isThisWeek {
					total.WeekMinutes += usage.Minutes
				}
				if isLastWeek {
					total.LastWeekMinutes += usage.Minutes
				}
				if usage.LastUpdated.After(total.LastSeen) {
					total.LastSeen = usage.LastUpdated
				}
				result[user] = total
			}
		}
	}

	return result
}
