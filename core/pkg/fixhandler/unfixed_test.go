package fixhandler

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
)

// --- helpers --------------------------------------------------------------

func failedRuleWithFix(path, value string) resourcesresults.ResourceAssociatedRule {
	return resourcesresults.ResourceAssociatedRule{
		Name:   "rule-" + path,
		Status: apis.StatusFailed,
		Paths: []armotypes.PosturePaths{
			{FixPath: armotypes.FixPath{Path: path, Value: value}},
		},
	}
}

func failedRuleNoFix() resourcesresults.ResourceAssociatedRule {
	// Failed rule with a FailedPath but no FixPath — this is the shape that
	// produces the silent-partial-remediation bug described in #2108.
	return resourcesresults.ResourceAssociatedRule{
		Name:   "rule-no-fix",
		Status: apis.StatusFailed,
		Paths: []armotypes.PosturePaths{
			{FailedPath: "spec.hostNetwork"},
		},
	}
}

func failedControl(id, name string, rules ...resourcesresults.ResourceAssociatedRule) resourcesresults.ResourceAssociatedControl {
	return resourcesresults.ResourceAssociatedControl{
		ControlID:               id,
		Name:                    name,
		Status:                  apis.StatusInfo{InnerStatus: apis.StatusFailed},
		ResourceAssociatedRules: rules,
	}
}

// buildResource constructs a reporthandling.Resource backed by a local YAML file
// at <baseDir>/<filename>. documentIndex is encoded into sourcePath as required
// by the fixhandler.
func buildResource(t *testing.T, baseDir, filename, kind, name string, documentIndex int) *reporthandling.Resource {
	t.Helper()

	obj := map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       kind,
		"metadata": map[string]interface{}{
			"name":      name,
			"namespace": "default",
		},
		"spec": map[string]interface{}{},
	}
	lw := localworkload.NewLocalWorkload(obj)
	lw.SetPath(filename + ":" + itoa(documentIndex))

	r := &reporthandling.Resource{
		ResourceID: lw.GetID(),
		Object:     lw.GetObject(),
		Source:     &reporthandling.Source{FileType: reporthandling.SourceTypeYaml, Path: baseDir},
	}
	return r
}

func itoa(i int) string {
	switch i {
	case 0:
		return "0"
	case 1:
		return "1"
	case 2:
		return "2"
	}
	// good enough for tests
	return "0"
}

func writeManifest(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return p
}

// newHandlerForResources spins up a FixHandler whose report contains the
// provided Results pointing at files inside baseDir.
func newHandlerForResources(baseDir string, results []resourcesresults.Result, resources []reporthandling.Resource, skipUserValues bool) *FixHandler {
	report := &reporthandlingv2.PostureReport{
		Metadata: reporthandlingv2.Metadata{
			ScanMetadata: reporthandlingv2.ScanMetadata{
				ScanningTarget: reporthandlingv2.Directory,
			},
			ContextMetadata: reporthandlingv2.ContextMetadata{
				DirectoryContextMetadata: &reporthandlingv2.DirectoryContextMetadata{
					BasePath: baseDir,
				},
			},
		},
		Results:   results,
		Resources: resources,
	}
	return &FixHandler{
		fixInfo:       &metav1.FixInfo{SkipUserValues: skipUserValues},
		reportObj:     report,
		localBasePath: baseDir,
	}
}

// --- controlHasOnlyUserValueFixes ----------------------------------------

func TestControlHasOnlyUserValueFixes(t *testing.T) {
	t.Run("all YOUR_-prefixed", func(t *testing.T) {
		ac := failedControl("C-X", "x",
			failedRuleWithFix("metadata.namespace", "YOUR_NAMESPACE"),
			failedRuleWithFix("spec.replicas", "YOUR_COUNT"),
		)
		assert.True(t, controlHasOnlyUserValueFixes(&ac))
	})
	t.Run("mixed", func(t *testing.T) {
		ac := failedControl("C-X", "x",
			failedRuleWithFix("metadata.namespace", "YOUR_NAMESPACE"),
			failedRuleWithFix("spec.containers[0].securityContext.privileged", "false"),
		)
		assert.False(t, controlHasOnlyUserValueFixes(&ac))
	})
	t.Run("no concrete-value fix", func(t *testing.T) {
		ac := failedControl("C-X", "x",
			failedRuleWithFix("spec.containers[0].securityContext.privileged", "false"),
		)
		assert.False(t, controlHasOnlyUserValueFixes(&ac))
	})
	t.Run("no fix paths at all", func(t *testing.T) {
		ac := failedControl("C-X", "x", failedRuleNoFix())
		assert.False(t, controlHasOnlyUserValueFixes(&ac))
	})
	t.Run("rule passed is ignored", func(t *testing.T) {
		ac := failedControl("C-X", "x")
		ac.ResourceAssociatedRules = []resourcesresults.ResourceAssociatedRule{
			{
				Name:   "passed-rule",
				Status: apis.StatusPassed,
				Paths: []armotypes.PosturePaths{
					{FixPath: armotypes.FixPath{Path: "x", Value: "1"}},
				},
			},
		}
		assert.False(t, controlHasOnlyUserValueFixes(&ac))
	})
}

// --- addYamlExpressionsFromResourceAssociatedControl ---------------------

func TestAddYamlExpressions_ReturnsWhetherAnythingAdded(t *testing.T) {
	t.Run("fixable rule adds expression", func(t *testing.T) {
		rfi := &ResourceFixInfo{YamlExpressions: map[string]armotypes.FixPath{}}
		ac := failedControl("C-1", "fixable",
			failedRuleWithFix("spec.containers[0].securityContext.privileged", "false"),
		)
		added := rfi.addYamlExpressionsFromResourceAssociatedControl(0, &ac, false)
		assert.True(t, added)
		assert.Len(t, rfi.YamlExpressions, 1)
	})
	t.Run("no fix path → not added", func(t *testing.T) {
		rfi := &ResourceFixInfo{YamlExpressions: map[string]armotypes.FixPath{}}
		ac := failedControl("C-2", "no-fix", failedRuleNoFix())
		added := rfi.addYamlExpressionsFromResourceAssociatedControl(0, &ac, false)
		assert.False(t, added)
		assert.Empty(t, rfi.YamlExpressions)
	})
	t.Run("YOUR_ value with skipUserValues → not added", func(t *testing.T) {
		rfi := &ResourceFixInfo{YamlExpressions: map[string]armotypes.FixPath{}}
		ac := failedControl("C-3", "user-val",
			failedRuleWithFix("metadata.namespace", "YOUR_NAMESPACE"),
		)
		added := rfi.addYamlExpressionsFromResourceAssociatedControl(0, &ac, true)
		assert.False(t, added)
		assert.Empty(t, rfi.YamlExpressions)
	})
	t.Run("YOUR_ value without skipUserValues → added", func(t *testing.T) {
		rfi := &ResourceFixInfo{YamlExpressions: map[string]armotypes.FixPath{}}
		ac := failedControl("C-3", "user-val",
			failedRuleWithFix("metadata.namespace", "YOUR_NAMESPACE"),
		)
		added := rfi.addYamlExpressionsFromResourceAssociatedControl(0, &ac, false)
		assert.True(t, added)
		assert.Len(t, rfi.YamlExpressions, 1)
	})
	t.Run("mixed YOUR_ + concrete with skipUserValues → only concrete added", func(t *testing.T) {
		rfi := &ResourceFixInfo{YamlExpressions: map[string]armotypes.FixPath{}}
		ac := failedControl("C-4", "mixed",
			failedRuleWithFix("metadata.namespace", "YOUR_NAMESPACE"),
			failedRuleWithFix("spec.containers[0].securityContext.privileged", "false"),
		)
		added := rfi.addYamlExpressionsFromResourceAssociatedControl(0, &ac, true)
		assert.True(t, added)
		assert.Len(t, rfi.YamlExpressions, 1)
	})
}

// --- PrepareResourcesToFix / classification ------------------------------

func TestPrepareResourcesToFix_ClassifiesFixedAndUnfixed(t *testing.T) {
	dir := t.TempDir()
	manifest := writeManifest(t, dir, "deploy.yaml", "apiVersion: apps/v1\nkind: Deployment\n")
	rel, err := filepath.Rel(dir, manifest)
	assert.NoError(t, err)

	res := buildResource(t, dir, rel, "Deployment", "demo", 0)

	results := []resourcesresults.Result{
		{
			ResourceID: res.GetID(),
			RawResource: res,
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				// fixable
				failedControl("C-0057", "Privileged container",
					failedRuleWithFix("spec.containers[0].securityContext.privileged", "false"),
				),
				// no auto-fix
				failedControl("C-0041", "HostNetwork access", failedRuleNoFix()),
				// passed control — must be ignored entirely
				{
					ControlID: "C-9999",
					Name:      "irrelevant",
					Status:    apis.StatusInfo{InnerStatus: apis.StatusPassed},
				},
			},
		},
	}
	h := newHandlerForResources(dir, results, nil, false)
	rtf := h.PrepareResourcesToFix(context.Background())

	assert.Len(t, rtf, 1, "one resource has at least one fixable control")
	assert.Equal(t, 1, h.FixedControlsCount(), "C-0057 is auto-fixable")
	if assert.Len(t, h.UnfixedControls(), 1, "C-0041 must be reported as unfixed") {
		u := h.UnfixedControls()[0]
		assert.Equal(t, "C-0041", u.ControlID)
		assert.Equal(t, "Deployment", u.ResourceKind)
		assert.Equal(t, "demo", u.ResourceName)
		assert.Contains(t, u.Reason, "no auto-fix")
	}
}

func TestPrepareResourcesToFix_SkipUserValuesReason(t *testing.T) {
	dir := t.TempDir()
	manifest := writeManifest(t, dir, "deploy.yaml", "apiVersion: apps/v1\nkind: Deployment\n")
	rel, _ := filepath.Rel(dir, manifest)
	res := buildResource(t, dir, rel, "Deployment", "demo", 0)

	results := []resourcesresults.Result{
		{
			ResourceID: res.GetID(),
			RawResource: res,
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				failedControl("C-0076", "Label usage",
					failedRuleWithFix("metadata.labels.app", "YOUR_APP"),
				),
			},
		},
	}
	h := newHandlerForResources(dir, results, nil, true /* skipUserValues */)
	_ = h.PrepareResourcesToFix(context.Background())

	assert.Equal(t, 0, h.FixedControlsCount())
	if assert.Len(t, h.UnfixedControls(), 1) {
		assert.Contains(t, h.UnfixedControls()[0].Reason, "user-supplied value")
	}
}

func TestPrepareResourcesToFix_MissingFile(t *testing.T) {
	dir := t.TempDir()
	// note: we deliberately do NOT create the manifest
	res := buildResource(t, dir, "ghost.yaml", "Deployment", "ghost", 0)

	results := []resourcesresults.Result{
		{
			ResourceID: res.GetID(),
			RawResource: res,
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				failedControl("C-0057", "Privileged",
					failedRuleWithFix("spec.privileged", "false"),
				),
			},
		},
	}
	h := newHandlerForResources(dir, results, nil, false)
	rtf := h.PrepareResourcesToFix(context.Background())
	assert.Empty(t, rtf)
	if assert.Len(t, h.UnfixedControls(), 1) {
		assert.Contains(t, h.UnfixedControls()[0].Reason, "file not found")
	}
}

func TestPrepareResourcesToFix_NonYamlSource(t *testing.T) {
	dir := t.TempDir()
	manifest := writeManifest(t, dir, "deploy.json", "{}")
	rel, _ := filepath.Rel(dir, manifest)
	res := buildResource(t, dir, rel, "Deployment", "demo", 0)
	res.Source.FileType = reporthandling.SourceTypeJson

	results := []resourcesresults.Result{
		{
			ResourceID: res.GetID(),
			RawResource: res,
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				failedControl("C-0057", "Privileged",
					failedRuleWithFix("spec.privileged", "false"),
				),
			},
		},
	}
	h := newHandlerForResources(dir, results, nil, false)
	_ = h.PrepareResourcesToFix(context.Background())
	if assert.Len(t, h.UnfixedControls(), 1) {
		assert.Contains(t, h.UnfixedControls()[0].Reason, "not a YAML")
	}
}

func TestPrepareResourcesToFix_PassedResultIgnored(t *testing.T) {
	dir := t.TempDir()
	manifest := writeManifest(t, dir, "deploy.yaml", "apiVersion: apps/v1\nkind: Deployment\n")
	rel, _ := filepath.Rel(dir, manifest)
	res := buildResource(t, dir, rel, "Deployment", "demo", 0)

	results := []resourcesresults.Result{
		{
			ResourceID:  res.GetID(),
			RawResource: res,
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				{ControlID: "C-0001", Status: apis.StatusInfo{InnerStatus: apis.StatusPassed}},
			},
		},
	}
	h := newHandlerForResources(dir, results, nil, false)
	rtf := h.PrepareResourcesToFix(context.Background())
	assert.Empty(t, rtf)
	assert.Empty(t, h.UnfixedControls())
	assert.Equal(t, 0, h.FixedControlsCount())
}

func TestPrepareResourcesToFix_ResetsBetweenCalls(t *testing.T) {
	dir := t.TempDir()
	manifest := writeManifest(t, dir, "deploy.yaml", "apiVersion: apps/v1\nkind: Deployment\n")
	rel, _ := filepath.Rel(dir, manifest)
	res := buildResource(t, dir, rel, "Deployment", "demo", 0)

	results := []resourcesresults.Result{
		{
			ResourceID:  res.GetID(),
			RawResource: res,
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				failedControl("C-0041", "HostNetwork", failedRuleNoFix()),
			},
		},
	}
	h := newHandlerForResources(dir, results, nil, false)

	_ = h.PrepareResourcesToFix(context.Background())
	assert.Len(t, h.UnfixedControls(), 1)
	_ = h.PrepareResourcesToFix(context.Background())
	assert.Len(t, h.UnfixedControls(), 1, "second call must not accumulate duplicates")
}

// --- PrintUnfixedControls dedup ------------------------------------------

func TestPrintUnfixedControls_Dedups(t *testing.T) {
	h := &FixHandler{
		fixedControlsCount: 1,
		unfixedControls: []UnfixedControl{
			{ControlID: "C-0041", ControlName: "HostNetwork", ResourceKind: "Deployment", ResourceName: "x", FilePath: "/f.yaml", Reason: "no auto-fix"},
			{ControlID: "C-0041", ControlName: "HostNetwork", ResourceKind: "Deployment", ResourceName: "x", FilePath: "/f.yaml", Reason: "no auto-fix"},
			{ControlID: "C-0038", ControlName: "HostPID", ResourceKind: "Deployment", ResourceName: "x", FilePath: "/f.yaml", Reason: "no auto-fix"},
		},
	}

	// We can't directly capture logger output here, but we can at least
	// verify it doesn't panic and the dedup helper logic doesn't blow up.
	h.PrintUnfixedControls()

	// And the underlying slice is unchanged (we only dedup at print time).
	assert.Len(t, h.unfixedControls, 3)
}

func TestPrintUnfixedControls_EmptyIsNoop(t *testing.T) {
	h := &FixHandler{}
	h.PrintUnfixedControls() // must not panic
}

// --- NewFixHandler input validation --------------------------------------

func TestNewFixHandler_RejectsYamlManifest(t *testing.T) {
	dir := t.TempDir()
	manifest := writeManifest(t, dir, "deploy.yaml", "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: x}\n")

	_, err := NewFixHandler(&metav1.FixInfo{ReportFile: manifest})
	if assert.Error(t, err) {
		assert.Contains(t, strings.ToLower(err.Error()), "does not look like a kubescape json scan report")
	}
}

func TestNewFixHandler_RejectsMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	bad := writeManifest(t, dir, "bad.json", `{"this": "is broken"`) // unterminated
	_, err := NewFixHandler(&metav1.FixInfo{ReportFile: bad})
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "failed to parse")
	}
}

func TestNewFixHandler_RejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	_, err := NewFixHandler(&metav1.FixInfo{ReportFile: dir})
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "directory")
	}
}

// --- ApplyChanges accounting --------------------------------------------

func TestApplyChanges_OnlyCountsSuccessfulWrites(t *testing.T) {
	dir := t.TempDir()
	manifest := writeManifest(t, dir, "deploy.yaml",
		"apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\nspec:\n  containers:\n  - name: c\n    image: nginx\n")

	// Make the file read-only so writeFixesToFile will fail even after the
	// in-memory fix succeeds. This is the exact corner the accounting bug hid:
	// pre-fix, the file was marked "updated" before the write was attempted.
	if err := os.Chmod(manifest, 0444); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	// Make the directory read-only too, otherwise os.WriteFile on Linux can
	// truncate-and-rewrite via the parent dir's perms on some filesystems.
	if err := os.Chmod(dir, 0555); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0755) })

	h := &FixHandler{fixInfo: &metav1.FixInfo{}, reportObj: &reporthandlingv2.PostureReport{}, localBasePath: dir}
	rfi := ResourceFixInfo{
		FilePath:        manifest,
		YamlExpressions: map[string]armotypes.FixPath{},
		DocumentIndex:   0,
	}
	rfi.YamlExpressions["select(di==0).spec.containers[0].image |= \"nginx:1.25\""] = armotypes.FixPath{
		Path: "spec.containers[0].image", Value: "nginx:1.25",
	}

	count, errs := h.ApplyChanges(context.Background(), []ResourceFixInfo{rfi})
	assert.Equal(t, 0, count, "write failed → file must not be counted as updated")
	assert.NotEmpty(t, errs)
}

func TestUnfixedControls_ReturnsCopy(t *testing.T) {
	h := &FixHandler{
		unfixedControls: []UnfixedControl{
			{ControlID: "C-0001", ControlName: "orig"},
		},
	}
	got := h.UnfixedControls()
	got[0].ControlName = "mutated"
	assert.Equal(t, "orig", h.unfixedControls[0].ControlName,
		"caller mutation must not leak into internal state")
}

func TestNewFixHandler_AcceptsValidReport(t *testing.T) {
	dir := t.TempDir()
	report := reporthandlingv2.PostureReport{
		Metadata: reporthandlingv2.Metadata{
			ScanMetadata: reporthandlingv2.ScanMetadata{
				ScanningTarget: reporthandlingv2.Directory,
			},
			ContextMetadata: reporthandlingv2.ContextMetadata{
				DirectoryContextMetadata: &reporthandlingv2.DirectoryContextMetadata{
					BasePath: dir,
				},
			},
		},
	}
	b, err := json.Marshal(report)
	assert.NoError(t, err)
	reportFile := filepath.Join(dir, "scan.json")
	assert.NoError(t, os.WriteFile(reportFile, b, 0644))

	h, err := NewFixHandler(&metav1.FixInfo{ReportFile: reportFile})
	assert.NoError(t, err)
	assert.NotNil(t, h)
}
