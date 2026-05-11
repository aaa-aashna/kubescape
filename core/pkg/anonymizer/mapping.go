package anonymizer

type Mapping struct {
	data map[string]string
}

func NewMapping() *Mapping {
	return &Mapping{
		data: make(map[string]string),
	}
}

func (m *Mapping) GetOrCreate(value string) string {
	if existing, ok := m.data[value]; ok {
		return existing
	}

	pseudo := value + "-hidden"

	m.data[value] = pseudo

	return pseudo
}
