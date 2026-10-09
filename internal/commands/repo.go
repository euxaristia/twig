package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/Twigpine/twig/internal/client"
	"github.com/Twigpine/twig/internal/did"
	"github.com/Twigpine/twig/internal/identity"
)

// RepoCreate creates a new repository on the node.
func RepoCreate(name, description string, private bool, branch, nodeURL, dirOverride string) error {
	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}

	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	body, _ := json.Marshal(map[string]interface{}{
		"name":           name,
		"description":    description,
		"is_public":      !private,
		"default_branch": branch,
	})

	resp, err := c.Post("/api/v1/repos", body)
	if err != nil {
		return fmt.Errorf("creating repo: %w", err)
	}

	return PrintResponseOrError(resp)
}

// RepoList lists repositories on the node.
func RepoList(nodeURL, dirOverride, format string) error {
	if format != "table" && format != "json" {
		return fmt.Errorf("unsupported output format %q (expected table or json)", format)
	}
	kp, _ := identity.LoadKeypair(dirOverride)
	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	resp, err := c.GetAuthed("/api/v1/repos")
	if err != nil {
		return fmt.Errorf("listing repos: %w", err)
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return PrintResponseOrError(resp)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}
	return writeRepoList(os.Stdout, data, format)
}

// RepoClonePrint prints the clone command for a repository.
func RepoClonePrint(name, nodeURL, dirOverride string) error {
	owner, repoName, err := ResolveRepoOwner(name, dirOverride)
	if err != nil {
		return err
	}

	fmt.Printf("git clone %s\n", client.FormatGitURL(owner, repoName))
	return nil
}

// RepoInfo retrieves repository metadata.
func RepoInfo(repoInput, nodeURL, dirOverride string) error {
	owner, name, err := ResolveRepoOwner(repoInput, dirOverride)
	if err != nil {
		return err
	}

	kp, _ := identity.LoadKeypair(dirOverride)
	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	resp, err := c.GetAuthed(fmt.Sprintf("/api/v1/repos/%s/%s", owner, name))
	if err != nil {
		return fmt.Errorf("fetching repo info: %w", err)
	}

	return PrintResponseOrError(resp)
}

// RepoCommits lists recent commits for a repository.
func RepoCommits(repoInput, branch string, limit int, nodeURL, dirOverride string) error {
	owner, name, err := ResolveRepoOwner(repoInput, dirOverride)
	if err != nil {
		return err
	}

	if branch == "" {
		branch = "main"
	}
	if limit <= 0 {
		limit = 20
	}

	kp, _ := identity.LoadKeypair(dirOverride)
	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	endpoint := fmt.Sprintf("/api/v1/repos/%s/%s/commits?branch=%s&limit=%d", owner, name, url.QueryEscape(branch), limit)
	resp, err := c.GetAuthed(endpoint)
	if err != nil {
		return fmt.Errorf("fetching commits: %w", err)
	}

	return PrintResponseOrError(resp)
}

// RepoFork forks a repository into the caller's namespace.
func RepoFork(repoInput, forkName, nodeURL, dirOverride string) error {
	owner, name, err := ResolveRepoOwner(repoInput, dirOverride)
	if err != nil {
		return err
	}

	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}

	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	body, _ := json.Marshal(map[string]interface{}{
		"name": forkName,
	})

	resp, err := c.Post(fmt.Sprintf("/api/v1/repos/%s/%s/fork", owner, name), body)
	if err != nil {
		return fmt.Errorf("forking repo: %w", err)
	}

	return PrintResponseOrError(resp)
}

// RepoLabelAdd adds a label to a repository.
func RepoLabelAdd(repoInput, label, nodeURL, dirOverride string) error {
	owner, name, err := ResolveRepoOwner(repoInput, dirOverride)
	if err != nil {
		return err
	}

	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}

	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	body, _ := json.Marshal(map[string]interface{}{
		"label": label,
	})

	resp, err := c.Post(fmt.Sprintf("/api/v1/repos/%s/%s/labels", owner, name), body)
	if err != nil {
		return fmt.Errorf("adding label: %w", err)
	}

	return PrintResponseOrError(resp)
}

// RepoLabelRemove removes a label from a repository.
func RepoLabelRemove(repoInput, label, nodeURL, dirOverride string) error {
	owner, name, err := ResolveRepoOwner(repoInput, dirOverride)
	if err != nil {
		return err
	}

	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}

	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	resp, err := c.Delete(fmt.Sprintf("/api/v1/repos/%s/%s/labels/%s", owner, name, url.PathEscape(label)), []byte("{}"))
	if err != nil {
		return fmt.Errorf("removing label: %w", err)
	}

	return PrintResponseOrError(resp)
}

// RepoLabelList lists labels on a repository.
func RepoLabelList(repoInput, nodeURL, dirOverride string) error {
	owner, name, err := ResolveRepoOwner(repoInput, dirOverride)
	if err != nil {
		return err
	}

	kp, _ := identity.LoadKeypair(dirOverride)
	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	resp, err := c.GetAuthed(fmt.Sprintf("/api/v1/repos/%s/%s/labels", owner, name))
	if err != nil {
		return fmt.Errorf("fetching labels: %w", err)
	}

	return PrintResponseOrError(resp)
}

// RepoOwner checks ownership and push permission for a repo.
func RepoOwner(repoInput, nodeURL, dirOverride string, outputJSON bool) error {
	owner, name, err := ResolveRepoOwner(repoInput, dirOverride)
	if err != nil {
		return err
	}

	kp, _ := identity.LoadKeypair(dirOverride)
	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	resp, err := c.GetAuthed(fmt.Sprintf("/api/v1/repos/%s/%s", owner, name))
	if err != nil {
		return fmt.Errorf("fetching repo: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("repo lookup failed (%d)", resp.StatusCode)
	}

	var repoInfo map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&repoInfo)

	repoOwner, _ := repoInfo["owner"].(string)
	if repoOwner == "" {
		repoOwner = owner
	}

	callerDID := ""
	if kp != nil {
		callerDID = kp.DID()
	}

	isOwner := (callerDID != "" && (callerDID == repoOwner || did.ShortDID(callerDID) == repoOwner))

	if outputJSON {
		return PrintJSON(map[string]interface{}{
			"repo":     fmt.Sprintf("%s/%s", owner, name),
			"owner":    repoOwner,
			"caller":   callerDID,
			"is_owner": isOwner,
			"can_push": isOwner,
		})
	}

	fmt.Printf("Repository: %s/%s\n", owner, name)
	fmt.Printf("Owner:      %s\n", repoOwner)
	if callerDID != "" {
		fmt.Printf("Caller DID: %s\n", callerDID)
		if isOwner {
			fmt.Println("Permission: owner (can push to protected branches)")
		} else {
			fmt.Println("Permission: contributor")
		}
	} else {
		fmt.Println("Caller:     anonymous")
	}

	return nil
}

// RepoReplicaRegister registers a replica node for a repository.
func RepoReplicaRegister(repoInput, replicaURL, nodeURL, dirOverride string) error {
	owner, name, err := ResolveRepoOwner(repoInput, dirOverride)
	if err != nil {
		return err
	}

	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}

	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	body, _ := json.Marshal(map[string]interface{}{
		"url": replicaURL,
	})

	resp, err := c.Post(fmt.Sprintf("/api/v1/repos/%s/%s/replicas", owner, name), body)
	if err != nil {
		return fmt.Errorf("registering replica: %w", err)
	}

	return PrintResponseOrError(resp)
}

// RepoReplicaUnregister unregisters a replica node for a repository.
func RepoReplicaUnregister(repoInput, nodeURL, dirOverride string) error {
	owner, name, err := ResolveRepoOwner(repoInput, dirOverride)
	if err != nil {
		return err
	}

	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}

	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	resp, err := c.Delete(fmt.Sprintf("/api/v1/repos/%s/%s/replicas", owner, name), []byte("{}"))
	if err != nil {
		return fmt.Errorf("unregistering replica: %w", err)
	}

	return PrintResponseOrError(resp)
}

// RepoReplicas lists replica nodes mirroring a repository.
func RepoReplicas(repoInput, nodeURL, dirOverride string) error {
	owner, name, err := ResolveRepoOwner(repoInput, dirOverride)
	if err != nil {
		return err
	}

	kp, _ := identity.LoadKeypair(dirOverride)
	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	resp, err := c.GetAuthed(fmt.Sprintf("/api/v1/repos/%s/%s/replicas", owner, name))
	if err != nil {
		return fmt.Errorf("listing replicas: %w", err)
	}

	return PrintResponseOrError(resp)
}
