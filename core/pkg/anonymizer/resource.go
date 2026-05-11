package anonymizer

import (
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
)

func anonymizeResources(allResources map[string]workloadinterface.IMetadata, mapping *Mapping) {
	for _, resource := range allResources {

		logger.L().Info(
			"before resource anonymization",
			helpers.String("name", resource.GetName()),
			helpers.String("namespace", resource.GetNamespace()),
		)

		if name := resource.GetName(); name != "" {
			resource.SetName(mapping.GetOrCreate(name))
		}

		if namespace := resource.GetNamespace(); namespace != "" {
			resource.SetNamespace(mapping.GetOrCreate(namespace))
		}

		logger.L().Info(
			"after resource anonymization",
			helpers.String("name", resource.GetName()),
			helpers.String("namespace", resource.GetNamespace()),
		)
	}
}