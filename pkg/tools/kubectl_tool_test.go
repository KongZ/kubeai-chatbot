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
