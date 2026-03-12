// Copyright 2026 Davide Guerri <davide.guerri@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dieTestEnv is the sentinel environment variable used to re-enter the test
// binary for subprocess-based die() path testing.
const dieTestEnv = "_LOADER_DIE_TEST"

// ── parseFlags ────────────────────────────────────────────────────────────────

func TestParseFlags_NoArgs(t *testing.T) {
	insecure, foreground, rest := parseFlags(nil)
	assert.False(t, insecure)
	assert.False(t, foreground)
	assert.Empty(t, rest)
}

func TestParseFlags_PositionalOnly(t *testing.T) {
	args := []string{"https://example.com", "token", "agent-1"}
	insecure, foreground, rest := parseFlags(args)
	assert.False(t, insecure)
	assert.False(t, foreground)
	assert.Equal(t, args, rest)
}

func TestParseFlags_InsecureFlag(t *testing.T) {
	insecure, foreground, rest := parseFlags([]string{"-k", "https://example.com", "token", "agent-1"})
	assert.True(t, insecure)
	assert.False(t, foreground)
	assert.Equal(t, []string{"https://example.com", "token", "agent-1"}, rest)
}

func TestParseFlags_ForegroundFlag(t *testing.T) {
	insecure, foreground, rest := parseFlags([]string{"-f", "https://example.com", "token", "agent-1"})
	assert.False(t, insecure)
	assert.True(t, foreground)
	assert.Equal(t, []string{"https://example.com", "token", "agent-1"}, rest)
}

func TestParseFlags_BothFlags(t *testing.T) {
	insecure, foreground, rest := parseFlags([]string{"-k", "-f", "https://example.com", "token", "agent-1"})
	assert.True(t, insecure)
	assert.True(t, foreground)
	assert.Equal(t, []string{"https://example.com", "token", "agent-1"}, rest)
}

func TestParseFlags_FlagsInReverseOrder(t *testing.T) {
	insecure, foreground, rest := parseFlags([]string{"-f", "-k", "https://example.com", "token", "agent-1"})
	assert.True(t, insecure)
	assert.True(t, foreground)
	assert.Equal(t, []string{"https://example.com", "token", "agent-1"}, rest)
}

func TestParseFlags_StopsAtFirstPositional(t *testing.T) {
	// A "-k" that appears after the first positional argument must not be
	// consumed as a flag.
	args := []string{"url", "-k", "token", "agent-1"}
	insecure, foreground, rest := parseFlags(args)
	assert.False(t, insecure)
	assert.False(t, foreground)
	assert.Equal(t, args, rest)
}

func TestParseFlags_UnknownFlag_Dies(t *testing.T) {
	if os.Getenv(dieTestEnv) != "" {
		parseFlags([]string{"-z"})
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestParseFlags_UnknownFlag_Dies")
	cmd.Env = append(os.Environ(), dieTestEnv+"=1")
	err := cmd.Run()
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	assert.Equal(t, 1, exitErr.ExitCode())
}

// ── hasCABundleAt ─────────────────────────────────────────────────────────────

func TestHasCABundleAt_ReturnsTrueWhenFileExists(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "ca-certificates.crt")
	require.NoError(t, os.WriteFile(bundle, []byte("fake ca bundle"), 0644))

	assert.True(t, hasCABundleAt([]string{bundle}))
}

func TestHasCABundleAt_ReturnsTrueForFirstMatch(t *testing.T) {
	dir := t.TempDir()
	second := filepath.Join(dir, "second.crt")
	require.NoError(t, os.WriteFile(second, []byte("cert"), 0644))

	assert.True(t, hasCABundleAt([]string{
		filepath.Join(dir, "missing.crt"), // does not exist
		second,
	}))
}

func TestHasCABundleAt_ReturnsFalseWhenNoneExist(t *testing.T) {
	assert.False(t, hasCABundleAt([]string{
		"/no/such/path/ca.crt",
		"/also/missing.pem",
	}))
}

func TestHasCABundleAt_EmptyList(t *testing.T) {
	assert.False(t, hasCABundleAt(nil))
}

func TestHasCABundle_Windows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only: system cert store always available")
	}
	assert.True(t, hasCABundle())
}

func TestHasCABundle_Unix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-only")
	}
	// On a normal dev/CI host at least one bundle path exists; verify the
	// function returns a consistent bool without panicking.
	result := hasCABundle()
	assert.IsType(t, bool(false), result)
}

// ── downloadToTemp ────────────────────────────────────────────────────────────

func TestDownloadToTemp_Success(t *testing.T) {
	const wantBody = "fake-agent-binary"
	const wantToken = "secret-jwt"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer "+wantToken, r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(wantBody))
	}))
	defer ts.Close()

	path := downloadToTemp(ts.Client(), ts.URL+"/dl/agent", wantToken)
	t.Cleanup(func() { _ = os.Remove(path) })

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, wantBody, string(content))

	info, err := os.Stat(path)
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0700), info.Mode().Perm())
	}
}

func TestDownloadToTemp_SendsBearerToken(t *testing.T) {
	var gotAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	path := downloadToTemp(ts.Client(), ts.URL, "tok123")
	t.Cleanup(func() { _ = os.Remove(path) })

	assert.Equal(t, "Bearer tok123", gotAuth)
}

func TestDownloadToTemp_NonOKStatus_Dies(t *testing.T) {
	if os.Getenv(dieTestEnv) != "" {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "not found", http.StatusNotFound)
		}))
		defer ts.Close()
		downloadToTemp(ts.Client(), ts.URL, "token")
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestDownloadToTemp_NonOKStatus_Dies")
	cmd.Env = append(os.Environ(), dieTestEnv+"=1")
	err := cmd.Run()
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	assert.Equal(t, 1, exitErr.ExitCode())
}

func TestDownloadToTemp_NetworkError_Dies(t *testing.T) {
	if os.Getenv(dieTestEnv) != "" {
		// Start and immediately close the server so the request fails.
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		url := ts.URL
		ts.Close()
		downloadToTemp(http.DefaultClient, url, "token")
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestDownloadToTemp_NetworkError_Dies")
	cmd.Env = append(os.Environ(), dieTestEnv+"=1")
	err := cmd.Run()
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	assert.Equal(t, 1, exitErr.ExitCode())
}
