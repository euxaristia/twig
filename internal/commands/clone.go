package commands

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Twigpine/twig/internal/client"
	"github.com/Twigpine/twig/internal/identity"
)

// Clone clones a Twigpine repository, configuring sparse-checkout if private subtrees are withheld.
func Clone(repoInput, destDir, branch, nodeURL, arweaveGateway, ipfsGateway string) error {
	if strings.HasPrefix(destDir, "-") {
		return fmt.Errorf("invalid destination directory %q: directory cannot start with '-'", destDir)
	}
	if strings.HasPrefix(branch, "-") {
		return fmt.Errorf("invalid branch %q: branch cannot start with '-'", branch)
	}

	owner, repoName, err := ResolveRepoOwner(repoInput, "")
	if err != nil {
		return err
	}

	if destDir == "" {
		destDir = repoName
	}

	remoteURL := client.FormatGitURL(owner, repoName)
	nodeURL = client.ResolveNodeURL(nodeURL)

	kp, _ := identity.LoadKeypair("")
	c := client.New(nodeURL, kp)

	// Fetch withheld paths
	withheld, reinclude, _ := fetchWithheldPaths(c, owner, repoName)

	if len(withheld) == 0 {
		args := []string{"clone"}
		if branch != "" {
			args = append(args, "--branch", branch)
		}
		args = append(args, "--", remoteURL, destDir)

		cmd := exec.Command("git", args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("git clone failed: %w", err)
		}
		return nil
	}

	// Partial clone with sparse-checkout
	fmt.Printf("Notice: repo has %d withheld private paths; configuring sparse clone\n", len(withheld))
	cloneArgs := []string{"clone", "--filter=blob:none", "--no-checkout", "--", remoteURL, destDir}
	cmd := exec.Command("git", cloneArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git partial clone failed: %w", err)
	}

	sparseCmd := exec.Command("git", "sparse-checkout", "init", "--no-cone")
	sparseCmd.Dir = destDir
	if err := sparseCmd.Run(); err != nil {
		return fmt.Errorf("git sparse-checkout init failed: %w", err)
	}

	// Build sparse-checkout spec
	var spec strings.Builder
	spec.WriteString("/*\n")
	for _, w := range withheld {
		pat := strings.TrimPrefix(w, "/")
		if strings.HasSuffix(pat, "/**") {
			pat = strings.TrimSuffix(pat, "/**") + "/"
		}
		spec.WriteString("!" + pat + "\n")
		spec.WriteString("!" + pat + "/\n")
	}
	for _, r := range reinclude {
		pat := strings.TrimPrefix(r, "/")
		spec.WriteString(pat + "\n")
		spec.WriteString(pat + "/\n")
	}

	sparseFile := filepath.Join(destDir, ".git", "info", "sparse-checkout")
	if err := os.WriteFile(sparseFile, []byte(spec.String()), 0644); err != nil {
		return fmt.Errorf("writing sparse-checkout spec: %w", err)
	}

	checkoutArgs := []string{"checkout"}
	if branch != "" {
		checkoutArgs = append(checkoutArgs, branch)
	}
	checkoutCmd := exec.Command("git", checkoutArgs...)
	checkoutCmd.Dir = destDir
	checkoutCmd.Stdout = os.Stdout
	checkoutCmd.Stderr = os.Stderr
	if err := checkoutCmd.Run(); err != nil {
		return fmt.Errorf("git checkout failed: %w", err)
	}

	return nil
}

func fetchWithheldPaths(c *client.NodeClient, owner, name string) ([]string, []string, error) {
	resp, err := c.GetAuthed(fmt.Sprintf("/api/v1/repos/%s/%s/withheld-paths", owner, name))
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, errors.New("no withheld paths endpoint")
	}

	var data struct {
		Withheld  []string `json:"withheld"`
		Reinclude []string `json:"reinclude"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, nil, err
	}

	return data.Withheld, data.Reinclude, nil
}
