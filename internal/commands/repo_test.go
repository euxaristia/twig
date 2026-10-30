package commands

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestWriteRepoListTable(t *testing.T) {
	const body = `[
		{"name":"shared","owner_did":"did:key:owner-one","is_public":true,"description":null,"updated_at":"2026-10-04T12:00:00Z"},
		{"name":"shared","owner_did":"did:key:owner-two","is_public":false,"description":"Private project","updated_at":"2026-10-03 12:00:00"},
		{"name":"日\t本\n語\u001b‮","owner_did":"did:key:owner\r-three","description":"safe\u0000text","updated_at":"short"},
		{"updated_at":"2026-02-30T12:00:00Z"},
		{"updated_at":"日本語の日時"}
	]`
	var out bytes.Buffer
	if err := writeRepoList(&out, []byte(body), "table"); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	want := []string{
		"NAME OWNER VISIBILITY UPDATED DESCRIPTION",
		"shared owner-one public 2026-10-04",
		"shared owner-two private 2026-10-03 Private project",
		"日本語 owner-three - - safetext",
		"- - - -",
		"- - - -",
	}
	if len(lines) != len(want) {
		t.Fatalf("got %d lines, want %d: %q", len(lines), len(want), out.String())
	}
	for i, line := range lines {
		if got := strings.Join(strings.Fields(line), " "); got != want[i] {
			t.Errorf("line %d: got %q, want %q", i, got, want[i])
		}
	}
	if strings.ContainsAny(out.String(), "\t\r\x00\x1b‮") {
		t.Errorf("unsafe or unexpanded table output: %q", out.String())
	}
}

func TestWriteRepoListLongCells(t *testing.T) {
	long := strings.Repeat("界", 201)
	data, err := json.Marshal([]repoListRow{{Name: long, OwnerDID: "did:key:" + long, Description: long}})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := writeRepoList(&out, data, "table"); err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")[1])
	for _, i := range []int{0, 1, 4} {
		if fields[i] != strings.Repeat("界", 200) {
			t.Errorf("cell %d not bounded by rune count: %q", i, fields[i])
		}
	}
}

func TestRepoCreateOptionInjection(t *testing.T) {
	err := RepoCreate("-flag", "description", false, "main", "", "")
	if err == nil || !strings.Contains(err.Error(), "name cannot start with '-'") {
		t.Errorf("expected error for flag-like repo name, got %v", err)
	}

	err = RepoCreate("valid-repo", "description", false, "-branch", "", "")
	if err == nil || !strings.Contains(err.Error(), "branch cannot start with '-'") {
		t.Errorf("expected error for flag-like branch, got %v", err)
	}
}

func TestRepoForkOptionInjection(t *testing.T) {
	err := RepoFork("owner/repo", "-fork", "", "")
	if err == nil || !strings.Contains(err.Error(), "name cannot start with '-'") {
		t.Errorf("expected error for flag-like fork name, got %v", err)
	}
}

func TestWriteRepoListJSON(t *testing.T) {
	body := `[{"name":"project","description":"` + strings.Repeat("x", 201) + `\n\u001b‮","star_count":9007199254740993,"unknown":{"number":9223372036854775807}}]`
	var out bytes.Buffer
	if err := writeRepoList(&out, []byte(body), "json"); err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, out.Bytes()); err != nil {
		t.Fatal(err)
	}
	if compact.String() != body {
		t.Fatalf("JSON fields were altered or truncated: %s", out.String())
	}
	if !strings.HasSuffix(out.String(), "\n") {
		t.Error("missing final newline")
	}
}

func TestWriteRepoListEmpty(t *testing.T) {
	for format, want := range map[string]string{"table": "No repositories found.\n", "json": "[]\n"} {
		t.Run(format, func(t *testing.T) {
			var out bytes.Buffer
			if err := writeRepoList(&out, []byte("[]"), format); err != nil {
				t.Fatal(err)
			}
			if out.String() != want {
				t.Errorf("got %q, want %q", out.String(), want)
			}
		})
	}
}

func TestWriteRepoListInvalidResponse(t *testing.T) {
	for _, format := range []string{"table", "json"} {
		for _, body := range []string{"", "[", "null", "{}", "1", "[null]", "[1]", `["repo"]`, "[{}] trailing", "[{}, false]"} {
			t.Run(format+"/"+body, func(t *testing.T) {
				var out bytes.Buffer
				if err := writeRepoList(&out, []byte(body), format); err == nil {
					t.Error("expected invalid response error")
				}
				if out.Len() != 0 {
					t.Errorf("partial success output: %q", out.String())
				}
			})
		}
	}
}

func TestWriteRepoListInvalidFields(t *testing.T) {
	var out bytes.Buffer
	if err := writeRepoList(&out, []byte(`[{"name":"valid"},{"name":42}]`), "table"); err == nil {
		t.Error("expected invalid field error")
	}
	if out.Len() != 0 {
		t.Errorf("partial success output: %q", out.String())
	}
}

type repoListErrorWriter struct {
	err error
}

func (w repoListErrorWriter) Write(p []byte) (int, error) {
	return 0, w.err
}

func TestWriteRepoListWriterFailure(t *testing.T) {
	failure := errors.New("writer failed")
	for _, format := range []string{"table", "json"} {
		for _, body := range []string{"[]", `[{"name":"project"}]`} {
			t.Run(format+"/"+body, func(t *testing.T) {
				if err := writeRepoList(repoListErrorWriter{failure}, []byte(body), format); !errors.Is(err, failure) {
					t.Errorf("got %v, want writer failure", err)
				}
			})
		}
	}
}
