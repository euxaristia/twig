package mcp

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Twigpine/twig/internal/client"
	"github.com/Twigpine/twig/internal/did"
	"github.com/Twigpine/twig/internal/identity"
	"github.com/Twigpine/twig/internal/ucan"
)

// Server handles MCP JSON-RPC 2.0 requests over stdin/stdout.
type Server struct {
	NodeURL string
	Keypair *identity.Keypair
	Client  *client.NodeClient
}

// NewServer creates a new MCP server instance.
func NewServer(nodeURL string, keypair *identity.Keypair) *Server {
	nodeClient := client.New(nodeURL, keypair)
	return &Server{
		NodeURL: nodeURL,
		Keypair: keypair,
		Client:  nodeClient,
	}
}

// Serve runs the main MCP JSON-RPC loop reading from in and writing to out.
func (s *Server) Serve(in io.Reader, out io.Writer) error {
	reader := bufio.NewReader(in)

	for {
		msgBytes, err := ReadMessage(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		var req struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      interface{}     `json:"id"`
			Method  string          `json:"method"`
			Params  json.RawMessage `json:"params"`
		}

		if err := json.Unmarshal(msgBytes, &req); err != nil {
			continue
		}

		resp := s.handleRequest(req.ID, req.Method, req.Params)
		if err := WriteMessage(out, resp); err != nil {
			return err
		}
	}
}

// ReadMessage parses an LSP-style Content-Length framed JSON message.
func ReadMessage(reader *bufio.Reader) ([]byte, error) {
	contentLength := -1

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "content-length:") {
			val := strings.TrimSpace(line[len("content-length:"):])
			if n, err := strconv.Atoi(val); err == nil {
				contentLength = n
			}
		}
	}

	if contentLength < 0 {
		return nil, errors.New("missing Content-Length header")
	}

	buf := make([]byte, contentLength)
	if _, err := io.ReadFull(reader, buf); err != nil {
		return nil, err
	}

	return buf, nil
}

// WriteMessage formats and writes an LSP-style Content-Length framed JSON message.
func WriteMessage(writer io.Writer, val interface{}) error {
	data, err := json.Marshal(val)
	if err != nil {
		return err
	}
	header := fmt.Sprintf("Content-Length: %d\r\n\r\n", len(data))
	if _, err := io.WriteString(writer, header); err != nil {
		return err
	}
	_, err = writer.Write(data)
	return err
}

func (s *Server) handleRequest(id interface{}, method string, paramsRaw json.RawMessage) map[string]interface{} {
	result, err := s.dispatch(method, paramsRaw)
	if err != nil {
		return map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      id,
			"error": map[string]interface{}{
				"code":    -32000,
				"message": err.Error(),
			},
		}
	}

	return map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  result,
	}
}

func (s *Server) dispatch(method string, paramsRaw json.RawMessage) (interface{}, error) {
	switch method {
	case "initialize":
		return map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]interface{}{
				"tools": map[string]interface{}{},
			},
			"serverInfo": map[string]interface{}{
				"name":    "twig",
				"version": "0.7.1",
			},
		}, nil

	case "notifications/initialized":
		return map[string]interface{}{}, nil

	case "ping":
		return map[string]interface{}{}, nil

	case "tools/list":
		return map[string]interface{}{
			"tools": ToolDefinitions(),
		}, nil

	case "tools/call":
		var callArgs struct {
			Name      string                 `json:"name"`
			Arguments map[string]interface{} `json:"arguments"`
		}
		if err := json.Unmarshal(paramsRaw, &callArgs); err != nil {
			return nil, fmt.Errorf("invalid tools/call params: %w", err)
		}

		out, err := s.callTool(callArgs.Name, callArgs.Arguments)
		if err != nil {
			return nil, err
		}

		return map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": out,
				},
			},
		}, nil

	default:
		return nil, fmt.Errorf("method not found: %s", method)
	}
}

func (s *Server) callTool(name string, args map[string]interface{}) (string, error) {
	switch name {
	case "identity_show":
		if s.Keypair == nil {
			return "", errors.New("no identity found — run `twig identity new` first")
		}
		return s.Keypair.DID(), nil

	case "identity_sign":
		if s.Keypair == nil {
			return "", errors.New("no identity found — run `twig identity new` first")
		}
		msg, _ := args["message"].(string)
		if msg == "" {
			return "", errors.New("missing 'message' argument")
		}
		return s.Keypair.SignB64([]byte(msg)), nil

	case "node_info":
		resp, err := s.Client.Get("/")
		if err != nil {
			return "", err
		}
		return readPretty(resp)

	case "node_health":
		resp, err := s.Client.Get("/health")
		if err != nil {
			return "", err
		}
		return readPretty(resp)

	case "repo_create":
		repoName, _ := args["name"].(string)
		if repoName == "" {
			return "", errors.New("missing 'name'")
		}
		body, _ := json.Marshal(map[string]interface{}{
			"name":        repoName,
			"description": args["description"],
			"is_public":   args["is_public"],
		})
		resp, err := s.Client.Post("/api/v1/repos", body)
		if err != nil {
			return "", err
		}
		return readPretty(resp)

	case "repo_list":
		resp, err := s.Client.Get("/api/v1/repos")
		if err != nil {
			return "", err
		}
		return readPretty(resp)

	case "repo_list_federated":
		resp, err := s.Client.Get("/api/v1/repos?federated=true")
		if err != nil {
			return "", err
		}
		return readPretty(resp)

	case "repo_get":
		repoName, _ := args["name"].(string)
		if repoName == "" {
			return "", errors.New("missing 'name'")
		}
		owner, _ := args["owner"].(string)
		if owner == "" {
			owner = s.resolveOwner()
		}
		resp, err := s.Client.Get(fmt.Sprintf("/api/v1/repos/%s/%s", owner, repoName))
		if err != nil {
			return "", err
		}
		return readPretty(resp)

	case "repo_commits":
		repoName, _ := args["name"].(string)
		if repoName == "" {
			return "", errors.New("missing 'name'")
		}
		owner, _ := args["owner"].(string)
		if owner == "" {
			owner = s.resolveOwner()
		}
		resp, err := s.Client.Get(fmt.Sprintf("/api/v1/repos/%s/%s/commits", owner, repoName))
		if err != nil {
			return "", err
		}
		return readPretty(resp)

	case "repo_tree":
		repoName, _ := args["name"].(string)
		if repoName == "" {
			return "", errors.New("missing 'name'")
		}
		owner, _ := args["owner"].(string)
		if owner == "" {
			owner = s.resolveOwner()
		}
		path, _ := args["path"].(string)
		resp, err := s.Client.Get(fmt.Sprintf("/api/v1/repos/%s/%s/tree?path=%s", owner, repoName, path))
		if err != nil {
			return "", err
		}
		return readPretty(resp)

	case "repo_clone_url":
		repoName, _ := args["name"].(string)
		if repoName == "" {
			return "", errors.New("missing 'name'")
		}
		owner, _ := args["owner"].(string)
		if owner == "" {
			owner = s.resolveOwner()
		}
		return client.FormatGitURL(owner, repoName), nil

	case "agent_register":
		if s.Keypair == nil {
			return "", errors.New("no identity found — run `twig identity new` first")
		}
		body, _ := json.Marshal(map[string]interface{}{
			"did":          s.Keypair.DID(),
			"capabilities": args["capabilities"],
			"model":        args["model"],
		})
		resp, err := s.Client.Post("/api/register", body)
		if err != nil {
			return "", err
		}
		return readPretty(resp)

	case "agent_capabilities":
		resp, err := s.Client.Get("/api/v1/capabilities")
		if err != nil {
			return "", err
		}
		return readPretty(resp)

	case "ucan_show":
		dir, _ := identity.DefaultDir("")
		data, err := os.ReadFile(dir + "/ucan.json")
		if err != nil {
			return "", fmt.Errorf("no UCAN found: %w", err)
		}
		return string(data), nil

	case "ucan_delegate":
		if s.Keypair == nil {
			return "", errors.New("no identity found — run `twig identity new` first")
		}
		to, _ := args["to"].(string)
		resource, _ := args["resource"].(string)
		action, _ := args["action"].(string)
		if to == "" || resource == "" || action == "" {
			return "", errors.New("missing 'to', 'resource', or 'action'")
		}

		var exp *time.Time
		if hours, ok := args["expiry_hours"].(float64); ok && hours > 0 {
			t := time.Now().Add(time.Duration(hours) * time.Hour)
			exp = &t
		}

		token, err := ucan.Issue(s.Keypair, to, []ucan.Capability{{With: resource, Can: action}}, exp)
		if err != nil {
			return "", err
		}
		return token.Encode()

	case "ucan_verify":
		tokenStr, _ := args["token"].(string)
		if tokenStr == "" {
			return "", errors.New("missing 'token'")
		}
		token, err := ucan.Decode(tokenStr)
		if err != nil {
			return "", err
		}
		sigErr := token.VerifySignature()
		res, _ := json.MarshalIndent(map[string]interface{}{
			"valid":           sigErr == nil && !token.IsExpired(),
			"signature_valid": sigErr == nil,
			"expired":         token.IsExpired(),
			"issuer":          token.Payload.Iss,
			"audience":        token.Payload.Aud,
			"capabilities":    token.Payload.Att,
			"expires":         token.Payload.Exp,
		}, "", "  ")
		return string(res), nil

	case "did_resolve":
		targetDID, _ := args["did"].(string)
		if targetDID == "" {
			return "", errors.New("missing 'did'")
		}
		doc := did.NewDIDDocument(targetDID)
		res, _ := json.MarshalIndent(doc, "", "  ")
		return string(res), nil

	case "pr_create":
		repo, _ := args["repo"].(string)
		owner, name := splitOwnerRepo(repo, s.resolveOwner())
		body, _ := json.Marshal(map[string]interface{}{
			"title":         args["title"],
			"source_branch": args["head"],
			"target_branch": args["base"],
			"body":          args["body"],
		})
		resp, err := s.Client.Post(fmt.Sprintf("/api/v1/repos/%s/%s/pulls", owner, name), body)
		if err != nil {
			return "", err
		}
		return readPretty(resp)

	case "pr_list":
		repo, _ := args["repo"].(string)
		owner, name := splitOwnerRepo(repo, s.resolveOwner())
		resp, err := s.Client.Get(fmt.Sprintf("/api/v1/repos/%s/%s/pulls", owner, name))
		if err != nil {
			return "", err
		}
		return readPretty(resp)

	case "pr_view":
		repo, _ := args["repo"].(string)
		owner, name := splitOwnerRepo(repo, s.resolveOwner())
		num := args["number"]
		resp, err := s.Client.Get(fmt.Sprintf("/api/v1/repos/%s/%s/pulls/%v", owner, name, num))
		if err != nil {
			return "", err
		}
		return readPretty(resp)

	case "pr_diff":
		repo, _ := args["repo"].(string)
		owner, name := splitOwnerRepo(repo, s.resolveOwner())
		num := args["number"]
		resp, err := s.Client.Get(fmt.Sprintf("/api/v1/repos/%s/%s/pulls/%v/diff", owner, name, num))
		if err != nil {
			return "", err
		}
		data, _ := io.ReadAll(resp.Body)
		return string(data), nil

	case "pr_merge":
		repo, _ := args["repo"].(string)
		owner, name := splitOwnerRepo(repo, s.resolveOwner())
		num := args["number"]
		resp, err := s.Client.Post(fmt.Sprintf("/api/v1/repos/%s/%s/pulls/%v/merge", owner, name, num), []byte("{}"))
		if err != nil {
			return "", err
		}
		return readPretty(resp)

	case "task_list":
		resp, err := s.Client.Get("/api/v1/tasks")
		if err != nil {
			return "", err
		}
		return readPretty(resp)

	case "task_create":
		body, _ := json.Marshal(args)
		resp, err := s.Client.Post("/api/v1/tasks", body)
		if err != nil {
			return "", err
		}
		return readPretty(resp)

	case "task_claim":
		id, _ := args["id"].(string)
		resp, err := s.Client.Post(fmt.Sprintf("/api/v1/tasks/%s/claim", id), []byte("{}"))
		if err != nil {
			return "", err
		}
		return readPretty(resp)

	case "task_complete":
		id, _ := args["id"].(string)
		body, _ := json.Marshal(map[string]interface{}{
			"result": args["result"],
		})
		resp, err := s.Client.Post(fmt.Sprintf("/api/v1/tasks/%s/complete", id), body)
		if err != nil {
			return "", err
		}
		return readPretty(resp)

	case "issue_list":
		repo, _ := args["repo"].(string)
		owner, name := splitOwnerRepo(repo, s.resolveOwner())
		resp, err := s.Client.Get(fmt.Sprintf("/api/v1/repos/%s/%s/issues", owner, name))
		if err != nil {
			return "", err
		}
		return readPretty(resp)

	case "issue_create":
		repo, _ := args["repo"].(string)
		owner, name := splitOwnerRepo(repo, s.resolveOwner())
		body, _ := json.Marshal(map[string]interface{}{
			"title": args["title"],
			"body":  args["body"],
		})
		resp, err := s.Client.Post(fmt.Sprintf("/api/v1/repos/%s/%s/issues", owner, name), body)
		if err != nil {
			return "", err
		}
		return readPretty(resp)

	case "bounty_list":
		resp, err := s.Client.Get("/api/v1/bounties")
		if err != nil {
			return "", err
		}
		return readPretty(resp)

	default:
		return "", fmt.Errorf("unknown tool: %s", name)
	}
}

func (s *Server) resolveOwner() string {
	if s.Keypair != nil {
		return did.ShortDID(s.Keypair.DID())
	}
	return "unknown"
}

func splitOwnerRepo(repo, defaultOwner string) (string, string) {
	if strings.Contains(repo, "/") {
		parts := strings.SplitN(repo, "/", 2)
		return parts[0], parts[1]
	}
	return defaultOwner, repo
}

func readPretty(resp *http.Response) (string, error) {
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var v interface{}
	if err := json.Unmarshal(data, &v); err == nil {
		pretty, err := json.MarshalIndent(v, "", "  ")
		if err == nil {
			return string(pretty), nil
		}
	}
	return string(data), nil
}

// ToolDefinitions returns the JSON-RPC tool definitions array for tools/list.
func ToolDefinitions() []map[string]interface{} {
	return []map[string]interface{}{
		{
			"name":        "identity_show",
			"description": "Return this agent's DID (decentralized identifier). No arguments needed.",
			"inputSchema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
		},
		{
			"name":        "identity_sign",
			"description": "Sign a message with this agent's Ed25519 private key. Returns base64url signature.",
			"inputSchema": map[string]interface{}{
				"type":     "object",
				"required": []string{"message"},
				"properties": map[string]interface{}{
					"message": map[string]interface{}{"type": "string", "description": "Message to sign (UTF-8)"},
				},
			},
		},
		{
			"name":        "node_info",
			"description": "Get metadata about the connected Twigpine node: DID, version, network, protocols.",
			"inputSchema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
		},
		{
			"name":        "node_health",
			"description": "Check if the Twigpine node is alive and responding.",
			"inputSchema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
		},
		{
			"name":        "repo_create",
			"description": "Create a new git repository on the node. Requires agent identity for auth.",
			"inputSchema": map[string]interface{}{
				"type":     "object",
				"required": []string{"name"},
				"properties": map[string]interface{}{
					"name":        map[string]interface{}{"type": "string", "description": "Repository name"},
					"description": map[string]interface{}{"type": "string", "description": "Short description"},
					"is_public":   map[string]interface{}{"type": "boolean", "description": "Public visibility", "default": true},
				},
			},
		},
		{
			"name":        "repo_list",
			"description": "List all repositories on the connected Twigpine node.",
			"inputSchema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
		},
		{
			"name":        "repo_list_federated",
			"description": "List repositories across ALL nodes in the Twigpine network (federation).",
			"inputSchema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
		},
		{
			"name":        "repo_get",
			"description": "Get metadata for a specific repository.",
			"inputSchema": map[string]interface{}{
				"type":     "object",
				"required": []string{"name"},
				"properties": map[string]interface{}{
					"name":  map[string]interface{}{"type": "string", "description": "Repository name"},
					"owner": map[string]interface{}{"type": "string", "description": "Owner DID (optional)"},
				},
			},
		},
		{
			"name":        "repo_commits",
			"description": "List recent commits for a repository with SHA-256 hashes, authors, and messages.",
			"inputSchema": map[string]interface{}{
				"type":     "object",
				"required": []string{"name"},
				"properties": map[string]interface{}{
					"name":  map[string]interface{}{"type": "string", "description": "Repository name"},
					"owner": map[string]interface{}{"type": "string", "description": "Owner (optional)"},
				},
			},
		},
		{
			"name":        "repo_tree",
			"description": "Browse the file tree of a repository at a given path.",
			"inputSchema": map[string]interface{}{
				"type":     "object",
				"required": []string{"name"},
				"properties": map[string]interface{}{
					"name":  map[string]interface{}{"type": "string", "description": "Repository name"},
					"path":  map[string]interface{}{"type": "string", "description": "Directory path", "default": ""},
					"owner": map[string]interface{}{"type": "string", "description": "Owner (optional)"},
				},
			},
		},
		{
			"name":        "repo_clone_url",
			"description": "Get twigpine:// clone URL for a repository.",
			"inputSchema": map[string]interface{}{
				"type":     "object",
				"required": []string{"name"},
				"properties": map[string]interface{}{
					"name":  map[string]interface{}{"type": "string", "description": "Repository name"},
					"owner": map[string]interface{}{"type": "string", "description": "Owner (optional)"},
				},
			},
		},
		{
			"name":        "agent_register",
			"description": "Register agent on the network.",
			"inputSchema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
		},
		{
			"name":        "agent_capabilities",
			"description": "List UCAN capability strings.",
			"inputSchema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
		},
		{
			"name":        "ucan_show",
			"description": "Show saved bootstrap UCAN.",
			"inputSchema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
		},
		{
			"name":        "ucan_delegate",
			"description": "Delegate capabilities to another agent.",
			"inputSchema": map[string]interface{}{
				"type":     "object",
				"required": []string{"to", "resource", "action"},
				"properties": map[string]interface{}{
					"to":       map[string]interface{}{"type": "string", "description": "Recipient DID"},
					"resource": map[string]interface{}{"type": "string", "description": "Resource URI"},
					"action":   map[string]interface{}{"type": "string", "description": "Action capability"},
				},
			},
		},
		{
			"name":        "ucan_verify",
			"description": "Verify a UCAN token.",
			"inputSchema": map[string]interface{}{
				"type":     "object",
				"required": []string{"token"},
				"properties": map[string]interface{}{
					"token": map[string]interface{}{"type": "string", "description": "UCAN JSON string"},
				},
			},
		},
		{
			"name":        "did_resolve",
			"description": "Resolve a DID to its document.",
			"inputSchema": map[string]interface{}{
				"type":     "object",
				"required": []string{"did"},
				"properties": map[string]interface{}{
					"did": map[string]interface{}{"type": "string", "description": "Target DID"},
				},
			},
		},
		{
			"name":        "pr_create",
			"description": "Open a pull request.",
			"inputSchema": map[string]interface{}{
				"type":     "object",
				"required": []string{"repo", "head", "title"},
				"properties": map[string]interface{}{
					"repo":  map[string]interface{}{"type": "string", "description": "Repository"},
					"head":  map[string]interface{}{"type": "string", "description": "Head branch"},
					"base":  map[string]interface{}{"type": "string", "description": "Base branch", "default": "main"},
					"title": map[string]interface{}{"type": "string", "description": "PR title"},
					"body":  map[string]interface{}{"type": "string", "description": "PR body"},
				},
			},
		},
		{
			"name":        "pr_list",
			"description": "List pull requests for a repo.",
			"inputSchema": map[string]interface{}{
				"type":     "object",
				"required": []string{"repo"},
				"properties": map[string]interface{}{
					"repo": map[string]interface{}{"type": "string", "description": "Repository"},
				},
			},
		},
		{
			"name":        "pr_view",
			"description": "Get a single pull request.",
			"inputSchema": map[string]interface{}{
				"type":     "object",
				"required": []string{"repo", "number"},
				"properties": map[string]interface{}{
					"repo":   map[string]interface{}{"type": "string", "description": "Repository"},
					"number": map[string]interface{}{"type": "integer", "description": "PR number"},
				},
			},
		},
		{
			"name":        "pr_diff",
			"description": "Get the diff for a pull request.",
			"inputSchema": map[string]interface{}{
				"type":     "object",
				"required": []string{"repo", "number"},
				"properties": map[string]interface{}{
					"repo":   map[string]interface{}{"type": "string", "description": "Repository"},
					"number": map[string]interface{}{"type": "integer", "description": "PR number"},
				},
			},
		},
		{
			"name":        "pr_merge",
			"description": "Merge a pull request.",
			"inputSchema": map[string]interface{}{
				"type":     "object",
				"required": []string{"repo", "number"},
				"properties": map[string]interface{}{
					"repo":   map[string]interface{}{"type": "string", "description": "Repository"},
					"number": map[string]interface{}{"type": "integer", "description": "PR number"},
				},
			},
		},
		{
			"name":        "task_list",
			"description": "List agent tasks.",
			"inputSchema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
		},
		{
			"name":        "task_create",
			"description": "Create a new task.",
			"inputSchema": map[string]interface{}{
				"type":     "object",
				"required": []string{"kind"},
				"properties": map[string]interface{}{
					"kind": map[string]interface{}{"type": "string", "description": "Task kind"},
				},
			},
		},
		{
			"name":        "task_claim",
			"description": "Claim a pending task.",
			"inputSchema": map[string]interface{}{
				"type":     "object",
				"required": []string{"id"},
				"properties": map[string]interface{}{
					"id": map[string]interface{}{"type": "string", "description": "Task ID"},
				},
			},
		},
		{
			"name":        "task_complete",
			"description": "Mark a task as completed.",
			"inputSchema": map[string]interface{}{
				"type":     "object",
				"required": []string{"id"},
				"properties": map[string]interface{}{
					"id":     map[string]interface{}{"type": "string", "description": "Task ID"},
					"result": map[string]interface{}{"type": "string", "description": "Result string"},
				},
			},
		},
		{
			"name":        "issue_list",
			"description": "List issues for a repo.",
			"inputSchema": map[string]interface{}{
				"type":     "object",
				"required": []string{"repo"},
				"properties": map[string]interface{}{
					"repo": map[string]interface{}{"type": "string", "description": "Repository"},
				},
			},
		},
		{
			"name":        "issue_create",
			"description": "Create a new issue.",
			"inputSchema": map[string]interface{}{
				"type":     "object",
				"required": []string{"repo", "title"},
				"properties": map[string]interface{}{
					"repo":  map[string]interface{}{"type": "string", "description": "Repository"},
					"title": map[string]interface{}{"type": "string", "description": "Title"},
					"body":  map[string]interface{}{"type": "string", "description": "Body"},
				},
			},
		},
		{
			"name":        "bounty_list",
			"description": "List bounties across the network.",
			"inputSchema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
		},
	}
}
