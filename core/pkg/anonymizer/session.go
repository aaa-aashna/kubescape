package anonymizer

import (
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/prioritization"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
)

func anonymizeSession(session *cautils.OPASessionObj, mapping *Mapping) {
	if session == nil {
		return
	}

	idMapping := make(map[string]string)

	newAllResources := make(map[string]workloadinterface.IMetadata, len(session.AllResources))
	for oldID, resource := range session.AllResources {
		if name := resource.GetName(); name != "" {
			resource.SetName(mapping.GetOrCreate("res", name))
		}

		if namespace := resource.GetNamespace(); namespace != "" {
			resource.SetNamespace(mapping.GetOrCreate("ns", namespace))
		}

		newID := resource.GetID()
		idMapping[oldID] = newID
		newAllResources[newID] = resource
	}
	session.AllResources = newAllResources

	newResourcesResult := make(map[string]resourcesresults.Result, len(session.ResourcesResult))
	for oldID, result := range session.ResourcesResult {
		newID := resolveMappedID(mapping, idMapping, oldID, "ref")
		result.ResourceID = newID

		if result.PrioritizedResource != nil {
			result.PrioritizedResource.ResourceID = newID
		}

		for controlIndex := range result.AssociatedControls {
			for ruleIndex := range result.AssociatedControls[controlIndex].ResourceAssociatedRules {
				rule := &result.AssociatedControls[controlIndex].ResourceAssociatedRules[ruleIndex]

				for pathIndex := range rule.Paths {
					rule.Paths[pathIndex].ResourceID = resolveMappedID(
						mapping,
						idMapping,
						rule.Paths[pathIndex].ResourceID,
						"ref",
					)
				}

				for relatedIndex := range rule.RelatedResourcesIDs {
					rule.RelatedResourcesIDs[relatedIndex] = resolveMappedID(
						mapping,
						idMapping,
						rule.RelatedResourcesIDs[relatedIndex],
						"ref",
					)
				}
			}
		}

		newResourcesResult[newID] = result
	}
	session.ResourcesResult = newResourcesResult

	newResourceSource := make(map[string]reporthandling.Source, len(session.ResourceSource))
	for oldID, source := range session.ResourceSource {
		newID := resolveMappedID(mapping, idMapping, oldID, "ref")
		newResourceSource[newID] = source
	}
	session.ResourceSource = newResourceSource

	newResourcesPrioritized := make(map[string]prioritization.PrioritizedResource, len(session.ResourcesPrioritized))
	for oldID, prioritized := range session.ResourcesPrioritized {
		newID := resolveMappedID(mapping, idMapping, oldID, "ref")
		prioritized.ResourceID = newID
		newResourcesPrioritized[newID] = prioritized
	}
	session.ResourcesPrioritized = newResourcesPrioritized

	newResourceAttackTracks := make(map[string]v1alpha1.IAttackTrack, len(session.ResourceAttackTracks))
	for oldID, attackTrack := range session.ResourceAttackTracks {
		newID := resolveMappedID(mapping, idMapping, oldID, "ref")
		newResourceAttackTracks[newID] = attackTrack
	}
	session.ResourceAttackTracks = newResourceAttackTracks
	if session.Report != nil {
		for controlID, control := range session.Report.SummaryDetails.Controls {
			remappedResourceIDs := control.ResourceIDs

			for oldID, status := range control.ResourceIDs.All() {
				newID := resolveMappedID(mapping, idMapping, oldID, "ref")

				if oldID != newID {
					delete(remappedResourceIDs.All(), oldID)
					remappedResourceIDs.Append(status, newID)
				}
			}

			control.ResourceIDs = remappedResourceIDs
			session.Report.SummaryDetails.Controls[controlID] = control
		}
	}
}

func resolveMappedID(mapping *Mapping, idMapping map[string]string, originalID, prefix string) string {
	if mappedID, ok := idMapping[originalID]; ok {
		return mappedID
	}

	return mapping.GetOrCreate(prefix, originalID)
}
