package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/GizmoTickler/fos1/pkg/leaderelection"
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

	// Sprint 31 / Ticket 47: HA via client-go leader election when the
	// in-cluster config is available. If the binary is invoked outside a
	// Pod (no service-account token) we run the runtime directly without
	// leader election so the unit/integration test harness still works.
	if restCfg, err := rest.InClusterConfig(); err == nil {
		kubeClient, err := kubernetes.NewForConfig(restCfg)
		if err != nil {
			log.Fatalf("build kube client: %v", err)
		}

		leNamespace := leaderelection.NamespaceFromEnv()
		if leNamespace == "" {
			log.Fatal("POD_NAMESPACE must be set (downward API) for leader election")
		}

		leErr := leaderelection.Run(ctx, leaderelection.Config{
			LockName:      "event-correlator.fos1.io",
			LockNamespace: leNamespace,
			Identity:      leaderelection.IdentityFromEnv(),
			Client:        kubeClient,
		}, func(leaderCtx context.Context) {
			if err := runtime.Run(leaderCtx); err != nil && leaderCtx.Err() == nil {
				log.Printf("run correlator: %v", err)
			}
		})
		if leErr != nil {
			log.Fatalf("leader election: %v", leErr)
		}
		return
	}

	if err := runtime.Run(ctx); err != nil {
		log.Fatalf("run correlator: %v", err)
	}
}
