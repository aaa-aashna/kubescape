package anonymizer

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/prioritization"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
)

// ── Mapping ───────────────────────────────────────────────────────────────────

func TestMapping_GetOrCreate_SameInputReturnsSameOutput(t *testing.T) {
	m := NewMapping()
	first := m.GetOrCreate("res", "my-pod")
	second := m.GetOrCreate("res", "my-pod")
	assert.Equal(t, first, second)
}

func TestMapping_GetOrCreate_DifferentInputsReturnDifferentOutputs(t *testing.T) {
	m := NewMapping()
	a := m.GetOrCreate("res", "pod-a")
	b := m.GetOrCreate("res", "pod-b")
	assert.NotEqual(t, a, b)
}

func TestMapping_GetOrCreate_PrefixIsolation(t *testing.T) {
	m := NewMapping()
	resVal := m.GetOrCreate("res", "myname")
	nsVal := m.GetOrCreate("ns", "myname")
	assert.NotEqual(t, resVal, nsVal)
	assert.Contains(t, resVal, "res-")
	assert.Contains(t, nsVal, "ns-")
}

// ── resolveMappedID ───────────────────────────────────────────────────────────

func TestResolveMappedID_KnownID(t *testing.T) {
	m := NewMapping()
	idMapping := map[string]string{"old-id": "new-id"}
	result := resolveMappedID(m, idMapping, "old-id", "ref")
	assert.Equal(t, "new-id", result)
}

func TestResolveMappedID_UnknownIDFallsBackToMapping(t *testing.T) {
	m := NewMapping()
	idMapping := map[string]string{}
	result := resolveMappedID(m, idMapping, "unknown-id", "ref")
	assert.NotEqual(t, "unknown-id", result)
	assert.Contains(t, result, "ref-")
}

// ── Apply ─────────────────────────────────────────────────────────────────────

func TestApply_NilHandler(t *testing.T) {
	assert.NoError(t, Apply(nil))
}

func TestApply_NilScanData(t *testing.T) {
	rh := &resultshandling.ResultsHandler{}
	assert.NoError(t, Apply(rh))
}

// ── anonymizeSession ──────────────────────────────────────────────────────────

func TestAnonymizeSession_NilSession(t *testing.T) {
	m := NewMapping()
	anonymizeSession(nil, m)
}

func TestAnonymizeSession_NamesAndNamespacesReplaced(t *testing.T) {
	pod := workloadinterface.NewWorkloadObj(map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name":      "my-secret-pod",
			"namespace": "my-secret-ns",
		},
	})

	oldID := pod.GetID()
	session := &cautils.OPASessionObj{
		AllResources:         map[string]workloadinterface.IMetadata{oldID: pod},
		ResourcesResult:      make(map[string]resourcesresults.Result),
		ResourceSource:       make(map[string]reporthandling.Source),
		ResourcesPrioritized: make(map[string]prioritization.PrioritizedResource),
		ResourceAttackTracks: make(map[string]v1alpha1.IAttackTrack),
	}

	m := NewMapping()
	anonymizeSession(session, m)

	for _, r := range session.AllResources {
		assert.NotEqual(t, "my-secret-pod", r.GetName())
		assert.NotEqual(t, "my-secret-ns", r.GetNamespace())
	}
}

func TestAnonymizeSession_IDConsistencyAcrossMaps(t *testing.T) {
	pod := workloadinterface.NewWorkloadObj(map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name":      "my-pod",
			"namespace": "default",
		},
	})

	oldID := pod.GetID()
	session := &cautils.OPASessionObj{
		AllResources: map[string]workloadinterface.IMetadata{oldID: pod},
		ResourcesResult: map[string]resourcesresults.Result{
			oldID: {ResourceID: oldID},
		},
		ResourceSource:       make(map[string]reporthandling.Source),
		ResourcesPrioritized: make(map[string]prioritization.PrioritizedResource),
		ResourceAttackTracks: make(map[string]v1alpha1.IAttackTrack),
	}

	m := NewMapping()
	anonymizeSession(session, m)

	var newID string
	for id := range session.AllResources {
		newID = id
	}

	_, inResult := session.ResourcesResult[newID]
	assert.True(t, inResult, "ResourcesResult must use the same remapped ID as AllResources")
}
