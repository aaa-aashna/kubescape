package v1

import (
	"os"
	"testing"

	"github.com/kubescape/kubescape/v3/httphandler/config"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	"github.com/stretchr/testify/assert"
)

func TestDefaultScanInfo(t *testing.T) {
	s := defaultScanInfo()

	assert.Equal(t, "", s.AccountID)
	assert.Equal(t, "v2", s.FormatVersion)
	assert.Equal(t, "json", s.Format)
	assert.Equal(t, "", s.AccessKey)
	assert.False(t, s.HostSensorEnabled.GetBool())
	assert.False(t, s.Local)
	assert.False(t, s.Submit)
}

func TestGetScanCommand(t *testing.T) {
	req := utilsmetav1.PostScanRequest{
		TargetType: apisv1.KindFramework,
	}
	s := getScanCommand(&req, "abc")
	assert.Equal(t, "", s.AccountID)
	assert.Equal(t, "abc", s.ScanID)
	assert.Equal(t, "v2", s.FormatVersion)
	assert.Equal(t, "json", s.Format)
	assert.Equal(t, "", s.AccessKey)
	assert.False(t, s.HostSensorEnabled.GetBool())
	assert.False(t, s.Local)
	assert.False(t, s.Submit)
}

func TestGetScanCommandWithAccessKey(t *testing.T) {
	config.SetAccessKey("test-123")

	req := utilsmetav1.PostScanRequest{
		TargetType: apisv1.KindFramework,
	}
	s := getScanCommand(&req, "abc")
	assert.Equal(t, "", s.AccountID)
	assert.Equal(t, "abc", s.ScanID)
	assert.Equal(t, "v2", s.FormatVersion)
	assert.Equal(t, "json", s.Format)
	assert.Equal(t, "test-123", s.AccessKey)
	assert.False(t, s.HostSensorEnabled.GetBool())
	assert.False(t, s.Local)
	assert.False(t, s.Submit)
}

func TestFindFile_EarlyExit(t *testing.T) {
	// Create a temp dir with multiple files
	dir := t.TempDir()
	// Create target file and extra files
	targetFile := dir + "/target-abc123.json"
	otherFile := dir + "/other-xyz.json"
	err := os.WriteFile(targetFile, []byte("{}"), 0644)
	assert.NoError(t, err)
	err = os.WriteFile(otherFile, []byte("{}"), 0644)
	assert.NoError(t, err)

	// findFile should find the target and stop early
	found, err := findFile(dir, "target-abc123")
	assert.NoError(t, err)
	assert.Contains(t, found, "target-abc123")
}

func TestFindFile_NotFound(t *testing.T) {
	dir := t.TempDir()
	found, err := findFile(dir, "nonexistent-file")
	assert.NoError(t, err)
	assert.Equal(t, "", found)
}

func TestFindFile_MissingDir(t *testing.T) {
	// WalkDir skips the root error same as per-entry errors; missing dir returns empty string and nil
	found, err := findFile("/nonexistent/dir", "file")
	assert.NoError(t, err)
	assert.Equal(t, "", found)
}
