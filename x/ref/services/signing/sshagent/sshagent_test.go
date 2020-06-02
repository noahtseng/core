package sshagent_test

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"v.io/x/ref/services/signing/sshagent"
)

func startAgent() (func(), error) {
	cmd := exec.Command("ssh-agent")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(output), "\n")
	first := lines[0]
	addr := strings.TrimPrefix(first, "SSH_AUTH_SOCK=")
	addr = strings.TrimSuffix(addr, "; export SSH_AUTH_SOCK;")
	sshagent.SetAgentAddress(func() string {
		return addr
	})
	second := lines[1]
	pidstr := strings.TrimPrefix(second, "SSH_AGENT_PID=")
	pidstr = strings.TrimSuffix(pidstr, "; export SSH_AGENT_PID;")
	pid, err := strconv.ParseInt(pidstr, 10, 64)
	if err != nil {
		return func() {}, fmt.Errorf("failed to parse pid from %v", second)
	}

	cleanup := func() {
		syscall.Kill(int(pid), syscall.SIGTERM)
		if testing.Verbose() {
			fmt.Println(string(output))
			fmt.Printf("killing: %v\n", int(pid))
		}
	}
	cmd = exec.Command("ssh-add",
		filepath.Join("testdata", "rsa"),
		filepath.Join("testdata", "ecdsa-256"),
		filepath.Join("testdata", "ecdsa-384"),
		filepath.Join("testdata", "ecdsa-521"),
		filepath.Join("testdata", "ed25519"))
	cmd.Env = []string{"SSH_AUTH_SOCK=" + addr}
	if output, err := cmd.CombinedOutput(); err != nil {
		return cleanup, fmt.Errorf("failed to add ssh keys: %v: %s", err, output)
	}
	return cleanup, nil
}

func TestMain(m *testing.M) {
	cleanup, err := startAgent()
	if err != nil {
		flag.Parse()
		cleanup()
		fmt.Fprintf(os.Stderr, "failed to start/configure agent: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

func TestAgentSigningVanadiumVerification(t *testing.T) {
	ctx := context.Background()
	service := sshagent.NewService()
	randSource := rand.New(rand.NewSource(time.Now().UnixNano()))
	for _, keyComment := range []string{
		"ecdsa-256",
		"ecdsa-384",
		"ecdsa-521",
	} {
		data := make([]byte, 4096)
		_, err := randSource.Read(data)
		if err != nil {
			t.Fatalf("rand: %v", err)
		}
		signer, publicKey, err := service.Signer(ctx, keyComment)
		if err != nil {
			t.Fatalf("service.Signer: %v", err)
		}
		sig, err := signer.Sign([]byte("testing"), data)
		if err != nil {
			t.Fatalf("signer.Sign: %v", err)
		}
		// Verify using Vanadium code.
		if !sig.Verify(publicKey, data) {
			t.Errorf("failed to verify signature")
		}
		data[1]++
		if sig.Verify(publicKey, data) {
			t.Errorf("failed to detect changed message")
		}
	}
	defer service.Close(ctx)
}
