package anonymizer

import (
	corev1 "k8s.io/api/core/v1"

	"github.com/kubescape/k8s-interface/workloadinterface"
)

func anonymizeContainerMetadata(resource workloadinterface.IMetadata, mapping *Mapping) {
	if resource == nil {
		return
	}

	obj := resource.GetObject()
	if obj == nil {
		return
	}

	anonymizePodSpecs(obj, mapping)
	resource.SetObject(obj)
}

func anonymizePodSpecs(node interface{}, mapping *Mapping) {
	switch v := node.(type) {
	case map[string]interface{}:
		anonymizeContainerList(v, "containers", mapping)
		anonymizeContainerList(v, "initContainers", mapping)
		anonymizeEphemeralContainerList(v, "ephemeralContainers", mapping)

		for _, child := range v {
			anonymizePodSpecs(child, mapping)
		}

	case []interface{}:
		for _, item := range v {
			anonymizePodSpecs(item, mapping)
		}
	}
}

func anonymizeContainerList(
	obj map[string]interface{},
	key string,
	mapping *Mapping,
) {
	rawContainers, ok := obj[key]
	if !ok || rawContainers == nil {
		return
	}

	containers, ok := rawContainers.([]corev1.Container)
	if !ok {
		return
	}

	for i := range containers {
		if containers[i].Name != "" {
			containers[i].Name = mapping.GetOrCreate("ctr", containers[i].Name)
		}

		if containers[i].Image != "" {
			containers[i].Image = mapping.GetOrCreate("img", containers[i].Image)
		}
	}

	obj[key] = containers
}

func anonymizeEphemeralContainerList(
	obj map[string]interface{},
	key string,
	mapping *Mapping,
) {
	rawContainers, ok := obj[key]
	if !ok || rawContainers == nil {
		return
	}

	containers, ok := rawContainers.([]corev1.EphemeralContainer)
	if !ok {
		return
	}

	for i := range containers {
		if containers[i].Name != "" {
			containers[i].Name = mapping.GetOrCreate("ctr", containers[i].Name)
		}

		if containers[i].Image != "" {
			containers[i].Image = mapping.GetOrCreate("img", containers[i].Image)
		}
	}

	obj[key] = containers
}
