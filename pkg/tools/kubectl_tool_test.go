package tools

import (
	"context"
	"os/exec"
	"testing"

	"github.com/KongZ/kubeai-chatbot/pkg/api"
	"github.com/stretchr/testify/assert"
)

func skipIfNoKubectl(t *testing.T) {
	if _, err := exec.LookPath("kubectl"); err != nil {
		t.Skip("kubectl binary not found in PATH, skipping test")
	}
}

func TestKubectlRun_Impersonation(t *testing.T) {
	skipIfNoKubectl(t)
	tool := NewKubectlTool()
	ctx := context.Background()
	ctx = context.WithValue(ctx, KubeconfigKey, "/tmp/kubeconfig")

	identity := &api.Identity{
		UserID: "user@example.com",
		Role:   "admin",
		Groups: []string{"dev", "qa"},
	}
	ctx = context.WithValue(ctx, IdentityKey, identity)

	args := map[string]any{
		"command": "kubectl get pods",
	}

	// We can't easily run it because it requires kubectl binary,
	// but we can test the internal logic if we refactor or just check if it compiles.
	// For now, let's just make sure it handles the command correctly.

	// Since Run executes the command, we might get an error if kubectl is missing,
	// but we can check the Command field in the result.
	result, err := tool.Run(ctx, args)
	assert.NoError(t, err)
	execResult := result.(*ExecResult)

	// The full command should have impersonation flags appended
	assert.Contains(t, execResult.Command, "--as=admin")
	assert.Contains(t, execResult.Command, "--as-group=dev")
	assert.Contains(t, execResult.Command, "--as-group=qa")
}

// TestIsInteractiveCommand verifies that compound commands (pipes, &&, ||, ;)
// are rejected at analysis time — before they are displayed to the user —
// alongside the existing interactive-mode checks (exec -it, port-forward, edit).
func TestIsInteractiveCommand(t *testing.T) {
	tests := []struct {
		name        string
		command     string
		wantBlocked bool
	}{
		// compound / piped commands — must be blocked
		{
			name:        "pipe to grep",
			command:     "kubectl get pods -A --context example-cluster | grep example-app",
			wantBlocked: true,
		},
		{
			name:        "pipe to awk",
			command:     "kubectl get pods -A | awk '{print $1}'",
			wantBlocked: true,
		},
		{
			name:        "logical AND chaining",
			command:     "kubectl get pods && kubectl get nodes",
			wantBlocked: true,
		},
		{
			name:        "logical OR chaining",
			command:     "kubectl get pods || echo failed",
			wantBlocked: true,
		},
		{
			name:        "semicolon chaining",
			command:     "kubectl get pods; kubectl get ns",
			wantBlocked: true,
		},
		// interactive commands — must be blocked
		{
			name:        "exec interactive",
			command:     "kubectl exec -it example-pod -- /bin/sh",
			wantBlocked: true,
		},
		{
			name:        "port-forward",
			command:     "kubectl port-forward svc/example-svc 8080:80",
			wantBlocked: true,
		},
		{
			name:        "edit",
			command:     "kubectl edit deployment example-deploy",
			wantBlocked: true,
		},
		// valid single commands — must pass through
		{
			name:        "simple get",
			command:     "kubectl get pods -A",
			wantBlocked: false,
		},
		{
			name:        "get with context",
			command:     "kubectl get pods -A --context example-cluster",
			wantBlocked: false,
		},
		{
			name:        "jsonpath output",
			command:     "kubectl get pods -o jsonpath='{.items[*].metadata.name}'",
			wantBlocked: false,
		},
		{
			name:        "field selector",
			command:     "kubectl get pods --field-selector=status.phase=Running",
			wantBlocked: false,
		},
		{
			name:        "label selector",
			command:     "kubectl get pods -l app=example-app",
			wantBlocked: false,
		},
		{
			name:        "empty command",
			command:     "",
			wantBlocked: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, err := IsInteractiveCommand(tt.command)
			if blocked != tt.wantBlocked {
				t.Errorf("IsInteractiveCommand(%q) blocked=%v, want %v (err=%v)",
					tt.command, blocked, tt.wantBlocked, err)
			}
			if tt.wantBlocked && err == nil {
				t.Errorf("IsInteractiveCommand(%q): expected non-nil error when blocked", tt.command)
			}
			if !tt.wantBlocked && err != nil {
				t.Errorf("IsInteractiveCommand(%q): unexpected error: %v", tt.command, err)
			}
		})
	}
}

func TestKubectlRun_InjectionPrevention(t *testing.T) {
	skipIfNoKubectl(t)
	tool := NewKubectlTool()
	ctx := context.Background()
	ctx = context.WithValue(ctx, KubeconfigKey, "/tmp/kubeconfig")

	identity := &api.Identity{
		UserID: "user@example.com",
		Role:   "admin; rm -rf /",
	}
	ctx = context.WithValue(ctx, IdentityKey, identity)

	args := map[string]any{
		"command": "kubectl get pods",
	}

	result, err := tool.Run(ctx, args)
	assert.NoError(t, err)
	execResult := result.(*ExecResult)

	// The command string should contain the semicolon, but since we execute directly,
	// it won't be interpreted as a shell command separator.
	assert.Contains(t, execResult.Command, "--as=admin; rm -rf /")
}
