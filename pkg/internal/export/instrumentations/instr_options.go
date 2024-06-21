package instrumentations

type Instrumentation string

type InstrumentationSelection map[Instrumentation]bool

const (
	InstrumentationHTTP  = "http"
	InstrumentationGRPC  = "grpc"
	InstrumentationSQL   = "sql"
	InstrumentationRedis = "redis"
	InstrumentationKafka = "kafka"
)

func NewInstrumentationSelection(instrumentations []string) InstrumentationSelection {
	selection := InstrumentationSelection{}
	for _, i := range instrumentations {
		selection[Instrumentation(i)] = true
	}

	return selection
}

func (s InstrumentationSelection) instrumentationEnabled(i Instrumentation) bool {
	_, ok := s[i]
	return ok
}

func (s InstrumentationSelection) HTTPEnabled() bool {
	return s.instrumentationEnabled(InstrumentationHTTP)
}

func (s InstrumentationSelection) GRPCEnabled() bool {
	return s.instrumentationEnabled(InstrumentationHTTP)
}

func (s InstrumentationSelection) SQLEnabled() bool {
	return s.instrumentationEnabled(InstrumentationHTTP)
}

func (s InstrumentationSelection) RedisEnabled() bool {
	return s.instrumentationEnabled(InstrumentationHTTP)
}

func (s InstrumentationSelection) DBEnabled() bool {
	return s.SQLEnabled() || s.RedisEnabled()
}

func (s InstrumentationSelection) KafkaEnabled() bool {
	return s.instrumentationEnabled(InstrumentationKafka)
}

func (s InstrumentationSelection) MQEnabled() bool {
	return s.KafkaEnabled()
}
