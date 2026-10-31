package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadWriteMessageRoundTrip(t *testing.T) {
	orig := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      float64(1),
		"method":  "ping",
	}

	var buf bytes.Buffer
	if err := WriteMessage(&buf, orig); err != nil {
		t.Fatalf("WriteMessage error: %v", err)
	}

	reader := bufio.NewReader(&buf)
	msgBytes, err := ReadMessage(reader)
	if err != nil {
		t.Fatalf("ReadMessage error: %v", err)
	}

	var recovered map[string]interface{}
	if err := json.Unmarshal(msgBytes, &recovered); err != nil {
		t.Fatalf("json unmarshal error: %v", err)
	}

	if recovered["method"] != "ping" || recovered["id"] != float64(1) {
		t.Fatalf("recovered msg mismatch: %v", recovered)
	}
}

func TestServerInitialize(t *testing.T) {
	srv := NewServer("https://node.gitlawb.com", nil)

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()

	go func() {
		_ = srv.Serve(inR, outW)
		outW.Close()
	}()

	req := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
	}

	go func() {
		_ = WriteMessage(inW, req)
		inW.Close()
	}()

	reader := bufio.NewReader(outR)
	respBytes, err := ReadMessage(reader)
	if err != nil {
		t.Fatalf("ReadMessage error: %v", err)
	}

	var resp struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Result  struct {
			ServerInfo struct {
				Name string `json:"name"`
			} `json:"serverInfo"`
		} `json:"result"`
	}

	if err := json.Unmarshal(respBytes, &resp); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if resp.Result.ServerInfo.Name != "twig" {
		t.Fatalf("expected server name 'twig', got %s", resp.Result.ServerInfo.Name)
	}
}

func TestToolCallEscaping(t *testing.T) {
	var requestedURI string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedURI = r.URL.RequestURI()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer ts.Close()

	srv := NewServer(ts.URL, nil)

	_, err := srv.callTool("repo_tree", map[string]interface{}{
		"name":  "my/repo",
		"owner": "user/sub",
		"path":  "src/file.txt?a=b&c=d",
	})
	if err != nil {
		t.Fatalf("callTool error: %v", err)
	}

	expectedURI := "/api/v1/repos/user%2Fsub/my%2Frepo/tree?path=src%2Ffile.txt%3Fa%3Db%26c%3Dd"
	if requestedURI != expectedURI {
		t.Errorf("expected requested URI %q, got %q", expectedURI, requestedURI)
	}
}

func TestReadMessageExceedsMaxContentLength(t *testing.T) {
	rawHeader := "Content-Length: 20000000\r\n\r\n"
	reader := bufio.NewReader(strings.NewReader(rawHeader))

	_, err := ReadMessage(reader)
	if err == nil {
		t.Fatal("expected error for exceeding MaxContentLength, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maximum limit") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestRepoCreateOptionInjectionMCP(t *testing.T) {
	srv := NewServer("https://node.gitlawb.com", nil)
	_, err := srv.callTool("repo_create", map[string]interface{}{
		"name": "-flag",
	})
	if err == nil || !strings.Contains(err.Error(), "name cannot start with '-'") {
		t.Errorf("expected error for flag-like repo name in MCP tool call, got %v", err)
	}
}

func TestPrCreateOptionInjectionMCP(t *testing.T) {
	srv := NewServer("https://node.gitlawb.com", nil)
	_, err := srv.callTool("pr_create", map[string]interface{}{
		"repo":  "owner/repo",
		"head":  "-evil-head",
		"base":  "main",
		"title": "Fix",
	})
	if err == nil || !strings.Contains(err.Error(), "invalid source branch \"-evil-head\": branch cannot start with '-'") {
		t.Errorf("expected error for flag-like head branch in MCP tool call, got %v", err)
	}

	_, err = srv.callTool("pr_create", map[string]interface{}{
		"repo":  "owner/repo",
		"head":  "feat",
		"base":  "-evil-base",
		"title": "Fix",
	})
	if err == nil || !strings.Contains(err.Error(), "invalid target branch \"-evil-base\": branch cannot start with '-'") {
		t.Errorf("expected error for flag-like base branch in MCP tool call, got %v", err)
	}
}
