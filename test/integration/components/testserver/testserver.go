package main

import (
	"os"

	"github.com/grafana/ebpf-autoinstrument/test/integration/components/testserver/gorilla"

	"github.com/grafana/ebpf-autoinstrument/test/integration/components/testserver/gin"
	"github.com/grafana/ebpf-autoinstrument/test/integration/components/testserver/std"

	"github.com/caarlos0/env/v7"
	gin2 "github.com/gin-gonic/gin"
	"golang.org/x/exp/slog"
)

/*
Server implementation to be used by integration tests.
Basically it's a server that accepts any method and path with a set of query parameters
that allow modifying its behavior (duration, response...)
*/

type config struct {
	// STDPort to listen connections using the standard library
	STDPort int `env:"STD_PORT" envDefault:"8080"`
	// GinPort to listen connections using the Gin framework
	GinPort int `env:"GIN_PORT" envDefault:"8081"`
	// GorillaPort to listen connections using the Gorilla Mux framework
	GorillaPort int    `env:"GIN_PORT" envDefault:"8082"`
	LogLevel    string `env:"LOG_LEVEL" envDefault:"INFO"`
}

func main() {
	cfg := config{}
	if err := env.Parse(&cfg); err != nil {
		slog.Error("can't load configuration from environment", err)
		os.Exit(-1)
	}
	setupLog(&cfg)

	wait := make(chan struct{})
	go func() {
		std.Setup(cfg.STDPort)
		close(wait)
	}()
	go func() {
		gin2.SetMode(gin2.ReleaseMode)
		gin.Setup(cfg.GinPort)
		close(wait)
	}()
	go func() {
		gorilla.Setup(cfg.GorillaPort)
		close(wait)
	}()

	// wait indefinitely unless any server crashes
	<-wait
	slog.Warn("stopping process")
}

func setupLog(cfg *config) {
	lvl := slog.LevelInfo
	err := lvl.UnmarshalText([]byte(cfg.LogLevel))
	if err != nil {
		slog.Error("unknown log level specified, choises are [DEBUG, INFO, WARN, ERROR]", err)
		os.Exit(-1)
	}
	ho := slog.HandlerOptions{
		Level: lvl,
	}
	slog.SetDefault(slog.New(ho.NewTextHandler(os.Stderr)))
	slog.Debug("logger is set", "level", lvl.String())
}
