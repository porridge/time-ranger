package sync

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAggregateTodayAndLastWeek(t *testing.T) {
	cluster := NewClusterState()

	now := time.Now()
	today := now.Format("2006-01-02")

	weekday := int(now.Weekday())
	if weekday == 0 {
		weekday = 7
	}
	thisMonday := now.AddDate(0, 0, -(weekday - 1))
	lastMonday := thisMonday.AddDate(0, 0, -7)
	twoWeeksAgo := thisMonday.AddDate(0, 0, -14)

	thisMondayStr := thisMonday.Format("2006-01-02")
	lastMondayStr := lastMonday.Format("2006-01-02")
	twoWeeksAgoStr := twoWeeksAgo.Format("2006-01-02")

	cluster.Nodes["node-1"] = NodeState{
		today: map[string]UserUsage{
			"alice": {Minutes: 30, LastUpdated: now},
		},
		thisMondayStr: map[string]UserUsage{
			"alice": {Minutes: 60, LastUpdated: thisMonday},
		},
		lastMondayStr: map[string]UserUsage{
			"alice": {Minutes: 100, LastUpdated: lastMonday},
			"bob":   {Minutes: 200, LastUpdated: lastMonday},
		},
		twoWeeksAgoStr: map[string]UserUsage{
			"alice": {Minutes: 999, LastUpdated: twoWeeksAgo},
		},
	}

	cluster.Nodes["node-2"] = NodeState{
		lastMondayStr: map[string]UserUsage{
			"bob": {Minutes: 50, LastUpdated: lastMonday},
		},
	}

	totals := cluster.AggregateToday()

	alice := totals["alice"]
	if today == thisMondayStr {
		// Today is Monday, so thisMonday is today
		require.Equal(t, 30.0, alice.TodayMinutes)
		require.Equal(t, 90.0, alice.WeekMinutes)
	} else {
		require.Equal(t, 30.0, alice.TodayMinutes)
		require.Equal(t, 90.0, alice.WeekMinutes)
	}
	require.Equal(t, 100.0, alice.LastWeekMinutes)
	require.Equal(t, 1, alice.Sources)

	bob := totals["bob"]
	require.Equal(t, 0.0, bob.TodayMinutes)
	require.Equal(t, 0.0, bob.WeekMinutes)
	require.Equal(t, 250.0, bob.LastWeekMinutes)
}

func TestGetUserWeekDetail(t *testing.T) {
	cluster := NewClusterState()

	now := time.Now()
	today := now.Format("2006-01-02")

	weekday := int(now.Weekday())
	if weekday == 0 {
		weekday = 7
	}
	thisMonday := now.AddDate(0, 0, -(weekday - 1))
	lastMonday := thisMonday.AddDate(0, 0, -7)

	lastMondayStr := lastMonday.Format("2006-01-02")

	cluster.Nodes["node-a"] = NodeState{
		today: map[string]UserUsage{
			"alice": {Minutes: 45, LastUpdated: now},
		},
		lastMondayStr: map[string]UserUsage{
			"alice": {Minutes: 90, LastUpdated: lastMonday},
		},
	}
	cluster.Nodes["node-b"] = NodeState{
		lastMondayStr: map[string]UserUsage{
			"alice": {Minutes: 30, LastUpdated: lastMonday},
		},
	}

	detail := cluster.GetUserWeekDetail("alice")

	require.Equal(t, "alice", detail.User)
	require.Contains(t, detail.Days, today)
	require.Len(t, detail.LastWeekDays, 7)
	require.Contains(t, detail.LastWeekDays, lastMondayStr)

	require.Equal(t, []string{"node-a", "node-b"}, detail.Machines)

	// Check current week grid
	require.Equal(t, 45.0, detail.Grid[today]["node-a"])
	require.Equal(t, 0.0, detail.Grid[today]["node-b"])
	require.Equal(t, 45.0, detail.Totals[today])

	// Check last week grid
	require.Equal(t, 90.0, detail.LastWeekGrid[lastMondayStr]["node-a"])
	require.Equal(t, 30.0, detail.LastWeekGrid[lastMondayStr]["node-b"])
	require.Equal(t, 120.0, detail.LastWeekTotals[lastMondayStr])
}
