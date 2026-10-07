package main

import (
	"flag"
	"testing"
)

func testFlagSet() (*flag.FlagSet, *bool, *string, *string) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	priv := fs.Bool("private", false, "")
	node := fs.String("node", "", "")
	title := fs.String("title", "", "")
	return fs, priv, node, title
}

func TestParseReorderedOptionsAfterPositionals(t *testing.T) {
	fs, priv, node, _ := testFlagSet()
	args := []string{"project", "--private", "--node", "https://selected.example"}
	if err := parseReordered(fs, args); err != nil {
		t.Fatalf("parseReordered failed: %v", err)
	}
	if !*priv {
		t.Fatalf("--private was dropped")
	}
	if *node != "https://selected.example" {
		t.Fatalf("--node was dropped, got %q", *node)
	}
	if got := fs.Args(); len(got) != 1 || got[0] != "project" {
		t.Fatalf("positionals = %v", got)
	}
}

func TestParseReorderedEqualsFormAndMixedOrder(t *testing.T) {
	fs, priv, node, title := testFlagSet()
	args := []string{"--private", "project", "--node=https://x.example", "--title", "hello world", "extra"}
	if err := parseReordered(fs, args); err != nil {
		t.Fatalf("parseReordered failed: %v", err)
	}
	if !*priv || *node != "https://x.example" || *title != "hello world" {
		t.Fatalf("flags dropped: private=%v node=%q title=%q", *priv, *node, *title)
	}
	if got := fs.Args(); len(got) != 2 || got[0] != "project" || got[1] != "extra" {
		t.Fatalf("positionals = %v", got)
	}
}

func TestParseReorderedDashDash(t *testing.T) {
	fs, priv, _, _ := testFlagSet()
	args := []string{"--", "--private"}
	if err := parseReordered(fs, args); err != nil {
		t.Fatalf("parseReordered failed: %v", err)
	}
	if *priv {
		t.Fatalf("--private after -- must stay positional")
	}
	if got := fs.Args(); len(got) != 1 || got[0] != "--private" {
		t.Fatalf("positionals = %v", got)
	}
}

func TestParseReorderedUnknownOption(t *testing.T) {
	fs, _, _, _ := testFlagSet()
	if err := parseReordered(fs, []string{"project", "--bogus"}); err == nil {
		t.Fatalf("expected error for unknown option")
	}
}

func TestParseReorderedMissingValue(t *testing.T) {
	fs, _, _, _ := testFlagSet()
	if err := parseReordered(fs, []string{"project", "--node"}); err == nil {
		t.Fatalf("expected error for missing option value")
	}
}

func TestParseReorderedBoolDoesNotEatPositional(t *testing.T) {
	fs, priv, _, _ := testFlagSet()
	args := []string{"--private", "project"}
	if err := parseReordered(fs, args); err != nil {
		t.Fatalf("parseReordered failed: %v", err)
	}
	if !*priv {
		t.Fatalf("--private not set")
	}
	if got := fs.Args(); len(got) != 1 || got[0] != "project" {
		t.Fatalf("boolean flag ate the positional: %v", got)
	}
}
