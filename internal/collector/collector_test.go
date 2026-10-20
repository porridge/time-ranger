package collector

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_getSomeUsers(t *testing.T) {
	tests := map[string]struct {
		cmd     *exec.Cmd
		want    []string
		wantErr string
	}{
		"basic": {
			cmd:  exec.Command("cat", "test_data/passwd.txt"),
			want: []string{"porridge", "user1", "user2", "testuser"},
		},
		"many": {
			cmd:  exec.Command("bash", "-c", "for i in $(seq 12);do echo \"testuser$i:x:100$i:100$i:Test User,,,:/home/testuser$i:/bin/bash\";done"),
			want: []string{"testuser1", "testuser2", "testuser3", "testuser4", "testuser5", "testuser6", "testuser7", "testuser8", "testuser9", "testuser10"},
		},
		"empty lines": {
			cmd:  exec.Command("bash", "-c", "echo;echo \"testuser$i:x:100$i:100$i:Test User,,,:/home/testuser$i:/bin/bash\";echo"),
			want: []string{"testuser"},
		},
		"bad": {
			cmd:     exec.Command("echo", "foo"),
			wantErr: "getent passwd: bad entry \"foo\"",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, gotErr := getSomeUsers(tt.cmd)
			if tt.wantErr != "" {
				require.EqualError(t, gotErr, tt.wantErr)
			} else {
				require.NoError(t, gotErr)
			}
			require.Equal(t, tt.want, got)
		})
	}
}
