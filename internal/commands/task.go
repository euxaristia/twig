package commands

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/Twigpine/twig/internal/client"
)

// TaskCreate creates a new agent task.
func TaskCreate(kind, capability, repoID, assigneeDID, payloadStr, ucanToken, deadline, nodeURL, dirOverride string) error {
	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}

	if capability == "" {
		capability = "agent:task"
	}

	body := map[string]interface{}{
		"kind":       kind,
		"capability": capability,
	}
	if repoID != "" {
		body["repo_id"] = repoID
	}
	if assigneeDID != "" {
		body["assignee_did"] = assigneeDID
	}
	if payloadStr != "" {
		var p interface{}
		if json.Unmarshal([]byte(payloadStr), &p) == nil {
			body["payload"] = p
		} else {
			body["payload"] = payloadStr
		}
	}
	if ucanToken != "" {
		body["ucan_token"] = ucanToken
	}
	if deadline != "" {
		body["deadline"] = deadline
	}

	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	bodyBytes, _ := json.Marshal(body)
	resp, err := c.Post("/api/v1/tasks", bodyBytes)
	if err != nil {
		return fmt.Errorf("creating task: %w", err)
	}

	return PrintResponseOrError(resp)
}

// TaskList lists tasks on the node.
func TaskList(status, assigneeDID string, limit int, nodeURL string) error {
	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, nil)

	q := url.Values{}
	if status != "" {
		q.Set("status", status)
	}
	if assigneeDID != "" {
		q.Set("assignee_did", assigneeDID)
	}
	if limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", limit))
	}

	path := "/api/v1/tasks"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}

	resp, err := c.Get(path)
	if err != nil {
		return fmt.Errorf("listing tasks: %w", err)
	}

	return PrintResponseOrError(resp)
}

// TaskView views a task by ID.
func TaskView(taskID, nodeURL string) error {
	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, nil)

	resp, err := c.Get(fmt.Sprintf("/api/v1/tasks/%s", url.PathEscape(taskID)))
	if err != nil {
		return fmt.Errorf("fetching task: %w", err)
	}

	return PrintResponseOrError(resp)
}

// TaskClaim claims a pending task.
func TaskClaim(taskID, nodeURL, dirOverride string) error {
	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}

	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	resp, err := c.Post(fmt.Sprintf("/api/v1/tasks/%s/claim", url.PathEscape(taskID)), []byte("{}"))
	if err != nil {
		return fmt.Errorf("claiming task: %w", err)
	}

	return PrintResponseOrError(resp)
}

// TaskComplete marks a task as completed.
func TaskComplete(taskID, result, nodeURL, dirOverride string) error {
	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}

	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	bodyBytes, _ := json.Marshal(map[string]interface{}{
		"result": result,
		"by_did": kp.DID(),
	})

	resp, err := c.Post(fmt.Sprintf("/api/v1/tasks/%s/complete", url.PathEscape(taskID)), bodyBytes)
	if err != nil {
		return fmt.Errorf("completing task: %w", err)
	}

	return PrintResponseOrError(resp)
}

// TaskFail marks a task as failed.
func TaskFail(taskID, reason, nodeURL, dirOverride string) error {
	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}

	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	bodyBytes, _ := json.Marshal(map[string]interface{}{
		"reason": reason,
		"by_did": kp.DID(),
	})

	resp, err := c.Post(fmt.Sprintf("/api/v1/tasks/%s/fail", url.PathEscape(taskID)), bodyBytes)
	if err != nil {
		return fmt.Errorf("failing task: %w", err)
	}

	return PrintResponseOrError(resp)
}
