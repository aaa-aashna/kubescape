package anonymizer

import (
	"github.com/kubescape/k8s-interface/workloadinterface"
)

func anonymizeResources(allResources map[string]workloadinterface.IMetadata, mapping *Mapping) {
	for _, resource := range allResources {

		if name := resource.GetName(); name != "" {
			resource.SetName(mapping.GetOrCreate(name))
		}

		if namespace := resource.GetNamespace(); namespace != "" {
			resource.SetNamespace(mapping.GetOrCreate(namespace))
		}

	}
}
