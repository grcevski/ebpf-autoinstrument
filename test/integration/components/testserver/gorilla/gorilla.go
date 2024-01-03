package gorilla

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/gorilla/mux"

	client "github.com/grafana/beyla/test/integration/components/testserver/grpc/client"
	"github.com/grafana/beyla/test/integration/components/testserver/std"
)

func Setup(port, stdPort int) {
	log := slog.With("component", "gorilla.Server")
	client, closer, err := client.NewDefaultClient()
	defer closer.Close()
	if err != nil {
		log.Error("Can't instantiate grpcClient", err)
		return
	}

	r := mux.NewRouter()
	r.PathPrefix("/").HandlerFunc(std.HTTPHandler(log, client, stdPort))

	address := fmt.Sprintf(":%d", port)
	log.Info("starting HTTP server", "address", address)
	err = http.ListenAndServe(address, r)
	log.Error("HTTP server has unexpectedly stopped", err)
}
