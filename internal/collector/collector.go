package collector

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Collector tracks screen time for members of a Unix group using timekpra or timekpr-next.
type Collector struct {
	GroupName string
	DataDir   string
}

// New creates a Collector for the given group and data directory.
func New(groupName, dataDir string) *Collector {
	return &Collector{GroupName: groupName, DataDir: dataDir}
}

// GetGroupMembers resolves all users that are members of the configured group.
func (c *Collector) GetGroupMembers() ([]string, error) {
	if c.GroupName == "" {
		return getSomeUsers(exec.Command("getent", "passwd"))
	}

	out, err := exec.Command("getent", "group", c.GroupName).Output()
	if err != nil {
		return nil, fmt.Errorf("getent group %s: %w", c.GroupName, err)
	}
	parts := strings.Split(strings.TrimSpace(string(out)), ":")
	if len(parts) < 4 || parts[3] == "" {
		return nil, nil
	}
	return strings.Split(parts[3], ","), nil
}

func getSomeUsers(cmd *exec.Cmd) ([]string, error) {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("getent passwd stdout: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("getent passwd start: %w", err)
	}
	scanner := bufio.NewScanner(stdout)
	var users []string
	for scanner.Scan() {
		if scanner.Text() == "" {
			continue
		}
		parts := strings.Split(scanner.Text(), ":")
		if len(parts) < 7 {
			return nil, fmt.Errorf("getent passwd: bad entry %q", scanner.Text())
		}
		name, home, shell := parts[0], parts[5], parts[6]
		if strings.HasSuffix(shell, "/nologin") || strings.HasSuffix(shell, "/false") || strings.HasPrefix(home, "/var") || strings.HasPrefix(home, "/bin") || strings.HasPrefix(home, "/root") || home == "/" {
			// probably a system user, according to our heuristics
			continue
		}
		if len(users) < 10 {
			// get at most 10, but drain stdout
			users = append(users, name)
		}
	}
	if scanner.Err() != nil {
		return nil, fmt.Errorf("getent passwd read: %w", err)
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("getent passwd finish: %w", err)
	}
	return users, nil
}

// CollectUserTime runs timekpra --userinfo <username> and parses TIME_SPENT_DAY.
// Returns minutes as a float64.
func (c *Collector) CollectUserTime(username string) (float64, error) {
	out, err := exec.Command("timekpra", "--userinfo", username).Output()
	if err != nil {
		return 0, fmt.Errorf("timekpra --userinfo %s: %w", username, err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == "TIME_SPENT_DAY:" {
			sec, err := strconv.ParseFloat(fields[1], 64)
			if err != nil {
				return 0, fmt.Errorf("parse TIME_SPENT_DAY for %s: %w", username, err)
			}
			return sec / 60.0, nil // convert to minutes
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("reading timekpra output for %s: %w", username, err)
	}
	return 0, fmt.Errorf("TIME_SPENT_DAY not found in timekpra output for %s", username)
}

// PersistLocal writes the daily usage to disk for survivability.
// File format: /var/lib/time-ranger/acct/<user>/<YYYY-MM-DD>
func (c *Collector) PersistLocal(user, date string, minutes float64) error {
	dir := filepath.Join(c.DataDir, "acct", user)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	filePath := filepath.Join(dir, date)
	return os.WriteFile(filePath, []byte(fmt.Sprintf("%.2f\n", minutes)), 0644)
}

// LoadPersisted reads a previously persisted daily value for a user.
func (c *Collector) LoadPersisted(user, date string) (float64, error) {
	filePath := filepath.Join(c.DataDir, "acct", user, date)
	data, err := os.ReadFile(filePath)
	if err != nil {
		return 0, err
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(string(data)), 64)
	if err != nil {
		return 0, err
	}
	return v, nil
}

// CollectOnce performs a single collection cycle: resolves group members,
// queries timekpra for each, persists results, and returns a snapshot of
// {username: minutes} for the current date.
func (c *Collector) CollectOnce() (map[string]float64, error) {
	members, err := c.GetGroupMembers()
	if err != nil {
		return nil, err
	}
	date := time.Now().Format("2006-01-02")
	result := make(map[string]float64)

	for _, user := range members {
		user = strings.TrimSpace(user)
		if user == "" {
			continue
		}
		mins, err := c.CollectUserTime(user)
		if err != nil {
			// Attempt to load persisted value on failure
			if persisted, persistErr := c.LoadPersisted(user, date); persistErr == nil {
				mins = persisted
			} else {
				continue
			}
		}
		if err := c.PersistLocal(user, date, mins); err != nil {
			return nil, err
		}
		result[user] = mins
	}
	return result, nil
}

// RunOnce runs CollectOnce and logs results. Returns error on failure.
func (c *Collector) RunOnce() error {
	data, err := c.CollectOnce()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[collector] error: %v\n", err)
		return err
	}
	for u, m := range data {
		fmt.Printf("[collector] %s: %.2f min\n", u, m)
	}
	return nil
}
func (c *Collector) GetLatestData() map[string]map[string]float64 {
	result := make(map[string]map[string]float64)
	acctDir := filepath.Join(c.DataDir, "acct")
	users, err := os.ReadDir(acctDir)
	if err != nil {
		return result
	}
	for _, u := range users {
		if !u.IsDir() {
			continue
		}
		username := u.Name()
		userDir := filepath.Join(acctDir, username)
		dates, err := os.ReadDir(userDir)
		if err != nil {
			continue
		}
		for _, d := range dates {
			if d.IsDir() {
				continue
			}
			date := d.Name()
			if v, err := c.LoadPersisted(username, date); err == nil {
				if _, ok := result[date]; !ok {
					result[date] = make(map[string]float64)
				}
				result[date][username] = v
			}
		}
	}
	return result
}
