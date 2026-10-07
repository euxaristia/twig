package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/Twigpine/twig/internal/commands"
	"github.com/Twigpine/twig/internal/identity"
	"github.com/Twigpine/twig/internal/mcp"
)

const version = "0.7.1"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "version", "--version", "-v":
		fmt.Printf("twig %s\n", version)
		return

	case "help", "--help", "-h":
		printUsage()
		return

	case "identity":
		handleIdentity(args)

	case "register":
		handleRegister(args)

	case "whoami":
		handleWhoami(args)

	case "clone":
		handleClone(args)

	case "repo":
		handleRepo(args)

	case "issue":
		handleIssue(args)

	case "pr":
		handlePR(args)

	case "peer":
		handlePeer(args)

	case "cert":
		handleCert(args)

	case "ipfs":
		handleIPFS(args)

	case "node":
		handleNode(args)

	case "webhook":
		handleWebhook(args)

	case "mirror":
		handleMirror(args)

	case "mcp":
		handleMCP(args)

	case "sync":
		handleSync(args)

	case "task":
		handleTask(args)

	case "name":
		handleName(args)

	case "doctor":
		handleDoctor(args)

	case "init":
		handleInit(args)

	case "quickstart":
		handleQuickstart(args)

	case "star":
		handleStar(args)

	case "status":
		handleStatus(args)

	case "agent":
		handleAgent(args)

	case "profile":
		handleProfile(args)

	case "protect":
		handleProtect(args)

	case "visibility":
		handleVisibility(args)

	case "changelog":
		handleChangelog(args)

	case "bounty":
		handleBounty(args)

	case "ucan":
		handleUcan(args)

	default:
		fmt.Fprintf(os.Stderr, "error: unknown command '%s'\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`twig — Twigpine decentralized git CLI (identity, repos, MCP server)

Usage: twig <command> [arguments...]

Commands:
  identity    Manage your Twigpine identity (DID + Ed25519 keypair)
  register    Register this agent with a Twigpine node
  clone       Clone a Twigpine repo, handling private subtrees cleanly
  repo        Manage repositories
  issue       Manage issues (stored as git refs)
  pr          Manage pull requests
  peer        Peer discovery — add and inspect known nodes
  cert        Inspect signed ref-update certificates
  ipfs        IPFS pin management and object retrieval
  node        Node status dashboard, network info, and on-chain ops
  webhook     Manage webhooks for a repository
  mirror      Mirror a public GitHub/GitLab repo into Twigpine
  mcp         MCP server — expose Twigpine tools to LLM agents
  sync        Sync repos from peer nodes
  task        Manage agent task delegation
  name        Register and resolve names on Base L2
  doctor      Check your Twigpine installation and connectivity
  init        Zero-to-push in one command
  quickstart  Interactive setup wizard
  star        Star and unstar repositories
  status      Snapshot of your current context
  agent       List and inspect registered agents on a node
  profile     Manage your agent profile (name, bio, avatar, socials)
  protect     Manage branch protection rules
  visibility  Manage path-scoped read visibility rules
  changelog   Show unified activity changelog for a repository
  bounty      Manage token-powered bounties on repositories
  ucan        Delegate, show, and verify UCAN capability tokens
  whoami      Print your current identity (DID) and node info
  version     Print version info`)
}

func parseFlags(name string, args []string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

func handleIdentity(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: twig identity <new|show|export|sign|backup|restore> [flags]")
		os.Exit(1)
	}
	sub := args[0]
	subArgs := args[1:]

	fs := parseFlags("identity "+sub, subArgs)
	dir := fs.String("dir", "", "Identity directory (default: ~/.twigpine)")

	switch sub {
	case "new":
		force := fs.Bool("force", false, "Overwrite existing keys without confirmation")
		_ = fs.Parse(subArgs)
		if err := commands.IdentityNew(*dir, *force, os.Stdin); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "show":
		_ = fs.Parse(subArgs)
		if err := commands.IdentityShow(*dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "export":
		_ = fs.Parse(subArgs)
		if err := commands.IdentityExport(*dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "sign":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: message required to sign")
			os.Exit(1)
		}
		if err := commands.IdentitySign(*dir, tail[0]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "backup":
		out := fs.String("out", "", "Destination path for backup file")
		_ = fs.Parse(subArgs)
		if err := commands.IdentityBackup(*dir, *out); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "restore":
		force := fs.Bool("force", false, "Overwrite existing identity without prompting")
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: path to backup file required")
			os.Exit(1)
		}
		if err := commands.IdentityRestore(*dir, tail[0], *force, os.Stdin); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "error: unknown identity command '%s'\n", sub)
		os.Exit(1)
	}
}

func handleRegister(args []string) {
	fs := parseFlags("register", args)
	node := fs.String("node", "", "Node URL to register with")
	caps := fs.String("capabilities", "git:push,git:fetch,issue:create,pr:open", "Comma-separated capabilities")
	model := fs.String("model", "", "Model/agent identifier")
	dir := fs.String("dir", "", "Identity directory")
	_ = fs.Parse(args)

	capList := strings.Split(*caps, ",")
	if err := commands.Register(*node, capList, *model, *dir); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func handleWhoami(args []string) {
	fs := parseFlags("whoami", args)
	node := fs.String("node", "", "Node URL to query")
	dir := fs.String("dir", "", "Identity directory")
	jsonOut := fs.Bool("json", false, "Output structured JSON")
	_ = fs.Parse(args)

	if err := commands.Whoami(*node, *dir, *jsonOut); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func handleClone(args []string) {
	fs := parseFlags("clone", args)
	branch := fs.String("branch", "", "Branch to check out")
	node := fs.String("node", "", "Node URL")
	arweave := fs.String("arweave-gateway", "https://arweave.net", "Arweave gateway URL")
	ipfs := fs.String("ipfs-gateway", "https://dweb.link", "IPFS gateway URL")
	_ = fs.Parse(args)

	tail := fs.Args()
	if len(tail) == 0 {
		fmt.Fprintln(os.Stderr, "error: repository required to clone: twig clone <repo> [dir]")
		os.Exit(1)
	}
	repo := tail[0]
	dest := ""
	if len(tail) > 1 {
		dest = tail[1]
	}

	if err := commands.Clone(repo, dest, *branch, *node, *arweave, *ipfs); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func handleRepo(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: twig repo <create|list|clone|info|commits|fork|label-add|label-remove|label-list|owner|replica-register|replica-unregister|replicas> [flags]")
		os.Exit(1)
	}
	sub := args[0]
	subArgs := args[1:]
	fs := parseFlags("repo "+sub, subArgs)
	node := fs.String("node", "", "Node URL")
	dir := fs.String("dir", "", "Identity directory")

	switch sub {
	case "create":
		desc := fs.String("description", "", "Repository description")
		priv := fs.Bool("private", false, "Make repository private")
		branch := fs.String("branch", "main", "Default branch")
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: repository name required")
			os.Exit(1)
		}
		if err := commands.RepoCreate(tail[0], *desc, *priv, *branch, *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "list":
		format := fs.String("format", "table", "Output format: table or json")
		outputJSON := fs.Bool("json", false, "Output the complete response as JSON")
		_ = fs.Parse(subArgs)
		if *format != "table" && *format != "json" {
			fmt.Fprintf(os.Stderr, "error: unsupported output format %q (expected table or json)\n", *format)
			os.Exit(1)
		}
		if *outputJSON {
			formatSet := false
			fs.Visit(func(f *flag.Flag) {
				if f.Name == "format" {
					formatSet = true
				}
			})
			if formatSet && *format != "json" {
				fmt.Fprintln(os.Stderr, "error: cannot combine --json with --format table")
				os.Exit(1)
			}
			*format = "json"
		}
		if err := commands.RepoList(*node, *dir, *format); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "clone":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: repository name required")
			os.Exit(1)
		}
		if err := commands.RepoClonePrint(tail[0], *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "info":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: repository name required")
			os.Exit(1)
		}
		if err := commands.RepoInfo(tail[0], *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "commits":
		branch := fs.String("branch", "main", "Branch name")
		limit := fs.Int("limit", 20, "Commit count limit")
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: repository name required")
			os.Exit(1)
		}
		if err := commands.RepoCommits(tail[0], *branch, *limit, *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "fork":
		name := fs.String("name", "", "New name for the fork")
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: repository name required")
			os.Exit(1)
		}
		if err := commands.RepoFork(tail[0], *name, *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "label-add":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) < 2 {
			fmt.Fprintln(os.Stderr, "error: repo and label required: twig repo label-add <repo> <label>")
			os.Exit(1)
		}
		if err := commands.RepoLabelAdd(tail[0], tail[1], *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "label-remove":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) < 2 {
			fmt.Fprintln(os.Stderr, "error: repo and label required: twig repo label-remove <repo> <label>")
			os.Exit(1)
		}
		if err := commands.RepoLabelRemove(tail[0], tail[1], *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "label-list":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: repo name required")
			os.Exit(1)
		}
		if err := commands.RepoLabelList(tail[0], *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "owner":
		jsonOut := fs.Bool("json", false, "Output JSON")
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: repo name required")
			os.Exit(1)
		}
		if err := commands.RepoOwner(tail[0], *node, *dir, *jsonOut); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "replica-register":
		urlVal := fs.String("url", "", "Public URL of replica node")
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 || *urlVal == "" {
			fmt.Fprintln(os.Stderr, "error: repo and --url required")
			os.Exit(1)
		}
		if err := commands.RepoReplicaRegister(tail[0], *urlVal, *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "replica-unregister":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: repo name required")
			os.Exit(1)
		}
		if err := commands.RepoReplicaUnregister(tail[0], *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "replicas":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: repo name required")
			os.Exit(1)
		}
		if err := commands.RepoReplicas(tail[0], *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "error: unknown repo command '%s'\n", sub)
		os.Exit(1)
	}
}

func handleIssue(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: twig issue <create|list|show|close|comment|comments> [flags]")
		os.Exit(1)
	}
	sub := args[0]
	subArgs := args[1:]
	fs := parseFlags("issue "+sub, subArgs)
	node := fs.String("node", "", "Node URL")
	dir := fs.String("dir", "", "Identity directory")

	switch sub {
	case "create":
		title := fs.String("title", "", "Issue title")
		body := fs.String("body", "", "Issue body")
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 || *title == "" {
			fmt.Fprintln(os.Stderr, "error: repo and --title required")
			os.Exit(1)
		}
		if err := commands.IssueCreate(tail[0], *title, *body, *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "list":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: repo name required")
			os.Exit(1)
		}
		if err := commands.IssueList(tail[0], *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "show":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) < 2 {
			fmt.Fprintln(os.Stderr, "error: repo and issue ID required: twig issue show <repo> <id>")
			os.Exit(1)
		}
		if err := commands.IssueShow(tail[0], tail[1], *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "close":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) < 2 {
			fmt.Fprintln(os.Stderr, "error: repo and issue ID required: twig issue close <repo> <id>")
			os.Exit(1)
		}
		if err := commands.IssueClose(tail[0], tail[1], *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "comment":
		body := fs.String("body", "", "Comment body")
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) < 2 || *body == "" {
			fmt.Fprintln(os.Stderr, "error: repo, issue ID, and --body required")
			os.Exit(1)
		}
		if err := commands.IssueComment(tail[0], tail[1], *body, *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "comments":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) < 2 {
			fmt.Fprintln(os.Stderr, "error: repo and issue ID required")
			os.Exit(1)
		}
		if err := commands.IssueComments(tail[0], tail[1], *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "error: unknown issue command '%s'\n", sub)
		os.Exit(1)
	}
}

func handlePR(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: twig pr <create|list|view|diff|merge|review|comment|comments> [flags]")
		os.Exit(1)
	}
	sub := args[0]
	subArgs := args[1:]
	fs := parseFlags("pr "+sub, subArgs)
	node := fs.String("node", "", "Node URL")
	dir := fs.String("dir", "", "Identity directory")

	switch sub {
	case "create":
		head := fs.String("head", "", "Head branch")
		base := fs.String("base", "main", "Base branch")
		title := fs.String("title", "", "PR title")
		body := fs.String("body", "", "PR body")
		owner := fs.String("owner", "", "Repo owner DID")
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 || *head == "" || *title == "" {
			fmt.Fprintln(os.Stderr, "error: repo, --head, and --title required")
			os.Exit(1)
		}
		if err := commands.PrCreate(tail[0], *head, *base, *title, *body, *owner, *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "list":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: repo required")
			os.Exit(1)
		}
		if err := commands.PrList(tail[0], *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "view":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) < 2 {
			fmt.Fprintln(os.Stderr, "error: repo and PR number required: twig pr view <repo> <number>")
			os.Exit(1)
		}
		num, _ := strconv.Atoi(tail[1])
		if err := commands.PrView(tail[0], num, *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "diff":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) < 2 {
			fmt.Fprintln(os.Stderr, "error: repo and PR number required")
			os.Exit(1)
		}
		num, _ := strconv.Atoi(tail[1])
		if err := commands.PrDiff(tail[0], num, *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "merge":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) < 2 {
			fmt.Fprintln(os.Stderr, "error: repo and PR number required")
			os.Exit(1)
		}
		num, _ := strconv.Atoi(tail[1])
		if err := commands.PrMerge(tail[0], num, *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "review":
		status := fs.String("status", "comment", "Review status (approved, changes_requested, comment)")
		body := fs.String("body", "", "Review body")
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) < 2 {
			fmt.Fprintln(os.Stderr, "error: repo and PR number required")
			os.Exit(1)
		}
		num, _ := strconv.Atoi(tail[1])
		if err := commands.PrReview(tail[0], num, *status, *body, *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "comment":
		body := fs.String("body", "", "Comment body")
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) < 2 || *body == "" {
			fmt.Fprintln(os.Stderr, "error: repo, PR number, and --body required")
			os.Exit(1)
		}
		num, _ := strconv.Atoi(tail[1])
		if err := commands.PrComment(tail[0], num, *body, *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "comments":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) < 2 {
			fmt.Fprintln(os.Stderr, "error: repo and PR number required")
			os.Exit(1)
		}
		num, _ := strconv.Atoi(tail[1])
		if err := commands.PrComments(tail[0], num, *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "error: unknown pr command '%s'\n", sub)
		os.Exit(1)
	}
}

func handlePeer(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: twig peer <list|add|ping|resolve> [flags]")
		os.Exit(1)
	}
	sub := args[0]
	subArgs := args[1:]
	fs := parseFlags("peer "+sub, subArgs)
	node := fs.String("node", "", "Node URL")
	dir := fs.String("dir", "", "Identity directory")

	switch sub {
	case "list":
		_ = fs.Parse(subArgs)
		if err := commands.PeerList(*node); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "add":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: peer URL required: twig peer add <peer_url>")
			os.Exit(1)
		}
		if err := commands.PeerAdd(tail[0], *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "ping":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: peer DID required")
			os.Exit(1)
		}
		if err := commands.PeerPing(tail[0], *node); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "resolve":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: peer DID required")
			os.Exit(1)
		}
		if err := commands.PeerResolve(tail[0], *node); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "error: unknown peer command '%s'\n", sub)
		os.Exit(1)
	}
}

func handleCert(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: twig cert <list|show> [flags]")
		os.Exit(1)
	}
	sub := args[0]
	subArgs := args[1:]
	fs := parseFlags("cert "+sub, subArgs)
	node := fs.String("node", "", "Node URL")
	dir := fs.String("dir", "", "Identity directory")

	switch sub {
	case "list":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: repo name required")
			os.Exit(1)
		}
		if err := commands.CertList(tail[0], *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "show":
		verify := fs.Bool("verify", false, "Cryptographically verify Ed25519 signature")
		expect := fs.String("expect-node", "", "Expected issuing node DID")
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) < 2 {
			fmt.Fprintln(os.Stderr, "error: repo and cert ID required: twig cert show <repo> <id>")
			os.Exit(1)
		}
		if err := commands.CertShow(tail[0], tail[1], *node, *dir, *verify, *expect); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "error: unknown cert command '%s'\n", sub)
		os.Exit(1)
	}
}

func handleIPFS(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: twig ipfs <list|get> [flags]")
		os.Exit(1)
	}
	sub := args[0]
	subArgs := args[1:]
	fs := parseFlags("ipfs "+sub, subArgs)
	node := fs.String("node", "", "Node URL")
	dir := fs.String("dir", "", "Identity directory")

	switch sub {
	case "list":
		_ = fs.Parse(subArgs)
		if err := commands.IpfsList(*node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "get":
		scan := fs.String("scan", "", "Resume token for scan continuation")
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: CID required: twig ipfs get <cid>")
			os.Exit(1)
		}
		if err := commands.IpfsGet(tail[0], *node, *dir, *scan); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "error: unknown ipfs command '%s'\n", sub)
		os.Exit(1)
	}
}

func handleNode(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: twig node <status|trust|resolve|register|heartbeat|onchain-status|claim|unstake-request|unstake> [flags]")
		os.Exit(1)
	}
	sub := args[0]
	subArgs := args[1:]
	fs := parseFlags("node "+sub, subArgs)
	node := fs.String("node", "", "Node URL")
	dir := fs.String("dir", "", "Identity directory")
	rpc := fs.String("rpc-url", "", "Base RPC URL")
	contract := fs.String("contract", "", "Contract address")
	privKey := fs.String("private-key", os.Getenv("GITLAWB_OPERATOR_PRIVATE_KEY"), "Operator private key")

	switch sub {
	case "status":
		_ = fs.Parse(subArgs)
		if err := commands.NodeStatus(*node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "trust":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: DID required: twig node trust <did>")
			os.Exit(1)
		}
		if err := commands.NodeTrust(tail[0], *node); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "resolve":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: DID required")
			os.Exit(1)
		}
		if err := commands.NodeResolve(tail[0], *node); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "register":
		stake := fs.Uint64("stake", 10000, "Stake amount")
		httpURL := fs.String("http-url", "", "Public HTTP URL of node")
		token := fs.String("token", os.Getenv("GITLAWB_TOKEN"), "Token address")
		_ = fs.Parse(subArgs)
		if *httpURL == "" {
			fmt.Fprintln(os.Stderr, "error: --http-url required")
			os.Exit(1)
		}
		if err := commands.NodeRegisterOnchain(*stake, *httpURL, *privKey, *rpc, *contract, *token); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "heartbeat":
		_ = fs.Parse(subArgs)
		if err := commands.NodeHeartbeat(*privKey, *rpc, *contract); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "onchain-status":
		_ = fs.Parse(subArgs)
		if err := commands.NodeOnchainStatus(*node, *rpc, *contract); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "claim":
		_ = fs.Parse(subArgs)
		if err := commands.NodeClaim(*privKey, *rpc, *contract); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "unstake-request":
		_ = fs.Parse(subArgs)
		if err := commands.NodeUnstakeRequest(*privKey, *rpc, *contract); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "unstake":
		_ = fs.Parse(subArgs)
		if err := commands.NodeUnstake(*privKey, *rpc, *contract); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "error: unknown node command '%s'\n", sub)
		os.Exit(1)
	}
}

func handleWebhook(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: twig webhook <create|list|delete> [flags]")
		os.Exit(1)
	}
	sub := args[0]
	subArgs := args[1:]
	fs := parseFlags("webhook "+sub, subArgs)
	node := fs.String("node", "", "Node URL")
	dir := fs.String("dir", "", "Identity directory")

	switch sub {
	case "create":
		hookURL := fs.String("url", "", "Webhook URL")
		events := fs.String("events", "*", "Events to subscribe to")
		secret := fs.String("secret", "", "HMAC secret")
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 || *hookURL == "" {
			fmt.Fprintln(os.Stderr, "error: repo and --url required: twig webhook create <repo> --url <url>")
			os.Exit(1)
		}
		if err := commands.WebhookCreate(tail[0], *hookURL, *events, *secret, *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "list":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: repo name required")
			os.Exit(1)
		}
		if err := commands.WebhookList(tail[0], *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "delete":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) < 2 {
			fmt.Fprintln(os.Stderr, "error: repo and webhook ID required: twig webhook delete <repo> <id>")
			os.Exit(1)
		}
		if err := commands.WebhookDelete(tail[0], tail[1], *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "error: unknown webhook command '%s'\n", sub)
		os.Exit(1)
	}
}

func handleMirror(args []string) {
	fs := parseFlags("mirror", args)
	repo := fs.String("repo", "", "Name on Twigpine")
	desc := fs.String("description", "", "Repository description")
	node := fs.String("node", "", "Node URL")
	dir := fs.String("dir", "", "Identity directory")
	_ = fs.Parse(args)

	tail := fs.Args()
	if len(tail) == 0 {
		fmt.Fprintln(os.Stderr, "error: source git URL required: twig mirror <source_url>")
		os.Exit(1)
	}

	if err := commands.Mirror(tail[0], *repo, *desc, *node, *dir); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func handleMCP(args []string) {
	if len(args) == 0 || args[0] != "serve" {
		fmt.Println("Usage: twig mcp serve [--node <url>] [--dir <path>]")
		os.Exit(1)
	}
	subArgs := args[1:]
	fs := parseFlags("mcp serve", subArgs)
	node := fs.String("node", "", "Node URL")
	dir := fs.String("dir", "", "Identity directory")
	_ = fs.Parse(subArgs)

	kp, _ := identity.LoadKeypair(*dir)
	nodeURL := *node
	if nodeURL == "" {
		nodeURL = "https://node.gitlawb.com"
	}

	srv := mcp.NewServer(nodeURL, kp)
	if err := srv.Serve(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "mcp server error: %v\n", err)
		os.Exit(1)
	}
}

func handleSync(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: twig sync <trigger|status> [flags]")
		os.Exit(1)
	}
	sub := args[0]
	subArgs := args[1:]
	fs := parseFlags("sync "+sub, subArgs)
	node := fs.String("node", "", "Node URL")
	dir := fs.String("dir", "", "Identity directory")
	_ = fs.Parse(subArgs)

	switch sub {
	case "trigger":
		if err := commands.SyncTrigger(*node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "status":
		if err := commands.SyncStatus(*node); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "error: unknown sync command '%s'\n", sub)
		os.Exit(1)
	}
}

func handleTask(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: twig task <create|list|view|claim|complete|fail> [flags]")
		os.Exit(1)
	}
	sub := args[0]
	subArgs := args[1:]
	fs := parseFlags("task "+sub, subArgs)
	node := fs.String("node", "", "Node URL")
	dir := fs.String("dir", "", "Identity directory")

	switch sub {
	case "create":
		capStr := fs.String("capability", "agent:task", "UCAN capability required")
		repoID := fs.String("repo-id", "", "Repo ID")
		assignee := fs.String("assignee-did", "", "Assignee DID")
		payload := fs.String("payload", "", "Task JSON payload")
		ucanTok := fs.String("ucan-token", "", "UCAN token")
		deadline := fs.String("deadline", "", "Deadline ISO-8601")
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: task kind required: twig task create <kind>")
			os.Exit(1)
		}
		if err := commands.TaskCreate(tail[0], *capStr, *repoID, *assignee, *payload, *ucanTok, *deadline, *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "list":
		status := fs.String("status", "", "Filter by status")
		assignee := fs.String("assignee-did", "", "Filter by assignee")
		limit := fs.Int("limit", 50, "Limit")
		_ = fs.Parse(subArgs)
		if err := commands.TaskList(*status, *assignee, *limit, *node); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "view":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: task ID required")
			os.Exit(1)
		}
		if err := commands.TaskView(tail[0], *node); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "claim":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: task ID required")
			os.Exit(1)
		}
		if err := commands.TaskClaim(tail[0], *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "complete":
		res := fs.String("result", "", "Result string")
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: task ID required")
			os.Exit(1)
		}
		if err := commands.TaskComplete(tail[0], *res, *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "fail":
		reason := fs.String("reason", "", "Failure reason")
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: task ID required")
			os.Exit(1)
		}
		if err := commands.TaskFail(tail[0], *reason, *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "error: unknown task command '%s'\n", sub)
		os.Exit(1)
	}
}

func handleName(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: twig name <register|resolve|lookup|available|register-did|resolve-did> [flags]")
		os.Exit(1)
	}
	sub := args[0]
	subArgs := args[1:]
	fs := parseFlags("name "+sub, subArgs)
	rpc := fs.String("rpc-url", "", "Base RPC URL")
	contract := fs.String("contract", "", "Registry contract address")
	privKey := fs.String("private-key", os.Getenv("ETH_PRIVATE_KEY"), "Ethereum private key")
	dir := fs.String("dir", "", "Identity directory")

	switch sub {
	case "resolve":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: name required: twig name resolve <name>")
			os.Exit(1)
		}
		if err := commands.NameResolve(tail[0], *rpc, *contract); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "lookup":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: DID required: twig name lookup <did>")
			os.Exit(1)
		}
		if err := commands.NameLookup(tail[0], *rpc, *contract); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "available":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: name required: twig name available <name>")
			os.Exit(1)
		}
		if err := commands.NameAvailable(tail[0], *rpc, *contract); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "register":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: name required: twig name register <name>")
			os.Exit(1)
		}
		if err := commands.NameRegister(tail[0], *privKey, *rpc, *contract, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "resolve-did":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: DID required")
			os.Exit(1)
		}
		if err := commands.NameResolveDID(tail[0], *rpc, *contract); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "register-did":
		_ = fs.Parse(subArgs)
		if err := commands.NameRegisterDID(*privKey, *rpc, *contract, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "error: unknown name command '%s'\n", sub)
		os.Exit(1)
	}
}

func handleDoctor(args []string) {
	fs := parseFlags("doctor", args)
	node := fs.String("node", "", "Node URL")
	dir := fs.String("dir", "", "Identity directory")
	_ = fs.Parse(args)

	if err := commands.Doctor(*node, *dir); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func handleInit(args []string) {
	fs := parseFlags("init", args)
	name := fs.String("name", "", "Repository name")
	desc := fs.String("description", "", "Repository description")
	node := fs.String("node", "", "Node URL")
	dir := fs.String("dir", "", "Identity directory")
	_ = fs.Parse(args)

	if err := commands.Init(*name, *desc, *node, *dir); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func handleQuickstart(args []string) {
	fs := parseFlags("quickstart", args)
	node := fs.String("node", "", "Node URL")
	dir := fs.String("dir", "", "Identity directory")
	yes := fs.Bool("yes", false, "Skip prompts")
	_ = fs.Parse(args)

	if err := commands.Quickstart(*node, *dir, *yes); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func handleStar(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: twig star <add|remove|count> <repo> [flags]")
		os.Exit(1)
	}
	sub := args[0]
	subArgs := args[1:]
	fs := parseFlags("star "+sub, subArgs)
	node := fs.String("node", "", "Node URL")
	dir := fs.String("dir", "", "Identity directory")
	_ = fs.Parse(subArgs)

	tail := fs.Args()
	if len(tail) == 0 {
		fmt.Fprintln(os.Stderr, "error: repo name required")
		os.Exit(1)
	}

	switch sub {
	case "add":
		if err := commands.StarAdd(tail[0], *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "remove":
		if err := commands.StarRemove(tail[0], *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "count":
		if err := commands.StarCount(tail[0], *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "error: unknown star command '%s'\n", sub)
		os.Exit(1)
	}
}

func handleStatus(args []string) {
	fs := parseFlags("status", args)
	node := fs.String("node", "", "Node URL")
	dir := fs.String("dir", "", "Identity directory")
	_ = fs.Parse(args)

	if err := commands.Status(*node, *dir); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func handleAgent(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: twig agent <list|show> [flags]")
		os.Exit(1)
	}
	sub := args[0]
	subArgs := args[1:]
	fs := parseFlags("agent "+sub, subArgs)
	node := fs.String("node", "", "Node URL")

	switch sub {
	case "list":
		capStr := fs.String("capability", "", "Filter by capability")
		_ = fs.Parse(subArgs)
		if err := commands.AgentList(*capStr, *node); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "show":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: agent DID required")
			os.Exit(1)
		}
		if err := commands.AgentShow(tail[0], *node); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "error: unknown agent command '%s'\n", sub)
		os.Exit(1)
	}
}

func handleProfile(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: twig profile <set|show|clear|pin> [flags]")
		os.Exit(1)
	}
	sub := args[0]
	subArgs := args[1:]
	fs := parseFlags("profile "+sub, subArgs)
	node := fs.String("node", "", "Node URL")
	dir := fs.String("dir", "", "Identity directory")

	switch sub {
	case "set":
		name := fs.String("name", "", "Display name")
		bio := fs.String("bio", "", "Bio")
		avatar := fs.String("avatar", "", "Avatar URL/CID")
		web := fs.String("website", "", "Website URL")
		twitter := fs.String("twitter", "", "Twitter handle")
		github := fs.String("github", "", "GitHub username")
		farcaster := fs.String("farcaster", "", "Farcaster handle")
		telegram := fs.String("telegram", "", "Telegram username")
		pin := fs.Bool("pin", false, "Pin to IPFS")
		_ = fs.Parse(subArgs)
		if err := commands.ProfileSet(*name, *bio, *avatar, *web, *twitter, *github, *farcaster, *telegram, *pin, *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "show":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		targetDID := ""
		if len(tail) > 0 {
			targetDID = tail[0]
		}
		if err := commands.ProfileShow(targetDID, *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "clear":
		_ = fs.Parse(subArgs)
		if err := commands.ProfileClear(*node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "pin":
		_ = fs.Parse(subArgs)
		if err := commands.ProfilePin(*node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "error: unknown profile command '%s'\n", sub)
		os.Exit(1)
	}
}

func handleProtect(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: twig protect <set|remove|list> [flags]")
		os.Exit(1)
	}
	sub := args[0]
	subArgs := args[1:]
	fs := parseFlags("protect "+sub, subArgs)
	repo := fs.String("repo", "", "Repository name")
	node := fs.String("node", "", "Node URL")
	dir := fs.String("dir", "", "Identity directory")

	switch sub {
	case "set":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 || *repo == "" {
			fmt.Fprintln(os.Stderr, "error: branch and --repo required: twig protect set <branch> --repo <repo>")
			os.Exit(1)
		}
		if err := commands.ProtectSet(tail[0], *repo, *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "remove":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 || *repo == "" {
			fmt.Fprintln(os.Stderr, "error: branch and --repo required: twig protect remove <branch> --repo <repo>")
			os.Exit(1)
		}
		if err := commands.ProtectRemove(tail[0], *repo, *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "list":
		_ = fs.Parse(subArgs)
		if *repo == "" {
			fmt.Fprintln(os.Stderr, "error: --repo required")
			os.Exit(1)
		}
		if err := commands.ProtectList(*repo, *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "error: unknown protect command '%s'\n", sub)
		os.Exit(1)
	}
}

func handleVisibility(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: twig visibility <set|remove|list> [flags]")
		os.Exit(1)
	}
	sub := args[0]
	subArgs := args[1:]
	fs := parseFlags("visibility "+sub, subArgs)
	repo := fs.String("repo", "", "Repository name")
	node := fs.String("node", "", "Node URL")
	dir := fs.String("dir", "", "Identity directory")

	switch sub {
	case "set":
		readers := fs.String("readers", "", "Comma-separated reader DIDs")
		mode := fs.String("mode", "b", "Mode: 'a' (hide) or 'b' (lock)")
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 || *repo == "" {
			fmt.Fprintln(os.Stderr, "error: path_glob and --repo required")
			os.Exit(1)
		}
		readerList := strings.Split(*readers, ",")
		if err := commands.VisibilitySet(tail[0], *repo, readerList, *mode, *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "remove":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 || *repo == "" {
			fmt.Fprintln(os.Stderr, "error: path_glob and --repo required")
			os.Exit(1)
		}
		if err := commands.VisibilityRemove(tail[0], *repo, *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "list":
		_ = fs.Parse(subArgs)
		if *repo == "" {
			fmt.Fprintln(os.Stderr, "error: --repo required")
			os.Exit(1)
		}
		if err := commands.VisibilityList(*repo, *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "error: unknown visibility command '%s'\n", sub)
		os.Exit(1)
	}
}

func handleChangelog(args []string) {
	fs := parseFlags("changelog", args)
	limit := fs.Int("limit", 20, "Maximum events to show")
	node := fs.String("node", "", "Node URL")
	dir := fs.String("dir", "", "Identity directory")
	_ = fs.Parse(args)

	tail := fs.Args()
	repo := ""
	if len(tail) > 0 {
		repo = tail[0]
	}

	if err := commands.Changelog(repo, *limit, *node, *dir); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func handleBounty(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: twig bounty <create|list|show|claim|submit|approve|cancel> [flags]")
		os.Exit(1)
	}
	sub := args[0]
	subArgs := args[1:]
	fs := parseFlags("bounty "+sub, subArgs)
	node := fs.String("node", "", "Node URL")
	dir := fs.String("dir", "", "Identity directory")

	switch sub {
	case "create":
		title := fs.String("title", "", "Bounty title")
		amount := fs.Int64("amount", 0, "Bounty amount")
		issue := fs.String("issue", "", "Issue ID")
		tx := fs.String("tx-hash", "", "Transaction hash")
		deadline := fs.Int64("deadline", 0, "Deadline in seconds")
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 || *title == "" || *amount <= 0 {
			fmt.Fprintln(os.Stderr, "error: repo, --title, and --amount required")
			os.Exit(1)
		}
		if err := commands.BountyCreate(tail[0], *title, *amount, *issue, *tx, *deadline, *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "list":
		repo := fs.String("repo", "", "Filter by repo")
		status := fs.String("status", "", "Filter by status")
		_ = fs.Parse(subArgs)
		if err := commands.BountyList(*repo, *status, *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "show":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: bounty ID required")
			os.Exit(1)
		}
		if err := commands.BountyShow(tail[0], *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "claim":
		wallet := fs.String("wallet", "", "Claimant wallet address")
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: bounty ID required")
			os.Exit(1)
		}
		if err := commands.BountyClaim(tail[0], *wallet, *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "submit":
		pr := fs.String("pr", "", "PR ID/number")
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 || *pr == "" {
			fmt.Fprintln(os.Stderr, "error: bounty ID and --pr required")
			os.Exit(1)
		}
		if err := commands.BountySubmit(tail[0], *pr, *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "approve":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: bounty ID required")
			os.Exit(1)
		}
		if err := commands.BountyApprove(tail[0], *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "cancel":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: bounty ID required")
			os.Exit(1)
		}
		if err := commands.BountyCancel(tail[0], *node, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "error: unknown bounty command '%s'\n", sub)
		os.Exit(1)
	}
}

func handleUcan(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: twig ucan <delegate|show|verify> [flags]")
		os.Exit(1)
	}
	sub := args[0]
	subArgs := args[1:]
	fs := parseFlags("ucan "+sub, subArgs)
	dir := fs.String("dir", "", "Identity directory")

	switch sub {
	case "delegate":
		to := fs.String("to", "", "Audience DID")
		capStr := fs.String("cap", "", "Resource capability URI")
		can := fs.String("can", "", "Action capability")
		expiry := fs.Int("expiry", 0, "Expiry in hours")
		out := fs.String("out", "", "Save UCAN to file")
		jsonOut := fs.Bool("json", false, "Output as JSON")
		_ = fs.Parse(subArgs)
		if *to == "" || *capStr == "" || *can == "" {
			fmt.Fprintln(os.Stderr, "error: --to, --cap, and --can required")
			os.Exit(1)
		}
		if err := commands.UcanDelegate(*to, *capStr, *can, *expiry, *out, *dir, *jsonOut); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "show":
		_ = fs.Parse(subArgs)
		if err := commands.UcanShow(*dir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "verify":
		_ = fs.Parse(subArgs)
		tail := fs.Args()
		if len(tail) == 0 {
			fmt.Fprintln(os.Stderr, "error: UCAN token or file required: twig ucan verify <token>")
			os.Exit(1)
		}
		if err := commands.UcanVerify(tail[0]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "error: unknown ucan command '%s'\n", sub)
		os.Exit(1)
	}
}
