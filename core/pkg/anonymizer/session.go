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
		if newID, ok := idMapping[oldID]; ok {
			result.ResourceID = newID

			if result.PrioritizedResource != nil {
				result.PrioritizedResource.ResourceID = newID
			}

			for controlIndex := range result.AssociatedControls {
				for ruleIndex := range result.AssociatedControls[controlIndex].ResourceAssociatedRules {
					rule := &result.AssociatedControls[controlIndex].ResourceAssociatedRules[ruleIndex]

					for pathIndex := range rule.Paths {
						oldPathID := rule.Paths[pathIndex].ResourceID
						if mappedPathID, exists := idMapping[oldPathID]; exists {
							rule.Paths[pathIndex].ResourceID = mappedPathID
						}
					}

					for relatedIndex := range rule.RelatedResourcesIDs {
						oldRelatedID := rule.RelatedResourcesIDs[relatedIndex]
						if mappedRelatedID, exists := idMapping[oldRelatedID]; exists {
							rule.RelatedResourcesIDs[relatedIndex] = mappedRelatedID
						}
					}
				}
			}

			newResourcesResult[newID] = result
		}
	}
	session.ResourcesResult = newResourcesResult

	newResourceSource := make(map[string]reporthandling.Source, len(session.ResourceSource))
	for oldID, source := range session.ResourceSource {
		if newID, ok := idMapping[oldID]; ok {
			newResourceSource[newID] = source
		}
	}
	session.ResourceSource = newResourceSource

	newResourcesPrioritized := make(map[string]prioritization.PrioritizedResource, len(session.ResourcesPrioritized))
	for oldID, prioritized := range session.ResourcesPrioritized {
		if newID, ok := idMapping[oldID]; ok {
			prioritized.ResourceID = newID
			newResourcesPrioritized[newID] = prioritized
		}
	}
	session.ResourcesPrioritized = newResourcesPrioritized

	newResourceAttackTracks := make(map[string]v1alpha1.IAttackTrack, len(session.ResourceAttackTracks))
	for oldID, attackTrack := range session.ResourceAttackTracks {
		if newID, ok := idMapping[oldID]; ok {
			newResourceAttackTracks[newID] = attackTrack
		}
	}
	session.ResourceAttackTracks = newResourceAttackTracks
}
