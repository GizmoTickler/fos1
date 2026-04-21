package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/GizmoTickler/fos1/pkg/security/ids/correlation"
)

func main() {
	var (
		configPath   string
		maxEvents    int
		maxAge       string
		outputFormat string
	)

	flag.StringVar(&configPath, "config", "/etc/correlator/config.json", "Path to the correlator config file")
	flag.IntVar(&maxEvents, "max-events", 0, "Override the maximum number of events kept in memory")
	flag.StringVar(&maxAge, "max-age", "", "Override the maximum event age")
	flag.StringVar(&outputFormat, "output-format", "", "Override the sink output format")
	flag.Parse()

	config, err := correlation.LoadConfig(configPath, correlation.ConfigOverrides{
		MaxEventsInMemory: maxEvents,
		MaxEventAge:       maxAge,
		OutputFormat:      outputFormat,
	})
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	runtime, err := correlation.NewRuntime(config, correlation.RuntimeOptions{
		HTTPAddr: ":8080",
	})
	if err != nil {
		log.Fatalf("create runtime: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := runtime.Run(ctx); err != nil {
		log.Fatalf("run correlator: %v", err)
	}
}
