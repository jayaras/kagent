/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	configv1 "github.com/kagent-dev/kagent/go/api/gen/kagent/config/v1"
	authimpl "github.com/kagent-dev/kagent/go/core/internal/httpserver/auth"
	"github.com/kagent-dev/kagent/go/core/pkg/app"
	"github.com/kagent-dev/kagent/go/core/pkg/auth"
	"github.com/kagent-dev/kagent/go/core/pkg/config"
)

func main() {
	path := flag.String("config", "/etc/kagent/controller.yaml", "Controller configuration file")
	check := flag.Bool("check-config", false, "Validate configuration and referenced files, then exit")
	level := flag.String("log-level", "", "Override the configured logging level")
	flag.Parse()
	if err := run(*path, *check, *level); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(path string, check bool, level string) error {
	cfg := &configv1.ControllerConfig{}
	if err := config.Load(path, cfg); err != nil {
		return err
	}
	config.DefaultController(cfg)
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "log-level" {
			cfg.Logging.Level = &level
		}
	})
	if err := config.Validate(cfg); err != nil {
		return err
	}
	config.ResolveControllerPaths(cfg, path)
	paths := []string{cfg.GetDatabase().GetReadWrite().GetUrlFile(), cfg.GetPush().GetSigningPrivateKeyFile()}
	// The owner login is unused when migrations are skipped, and its Secret may not be mounted.
	if !cfg.GetDatabase().GetSkipMigrations() {
		paths = append(paths, cfg.GetDatabase().GetOwner().GetUrlFile())
	}
	for _, path := range paths {
		if path == "" {
			continue
		}
		if _, err := config.ReadSecret(path); err != nil {
			return err
		}
	}
	anthropicSelfHostedSandboxesConfig, err := loadAnthropicSelfHostedSandboxesConfig(os.Getenv) //nolint:forbidigo // Registered integration settings read once at the executable boundary.
	if err != nil {
		slog.Default().Error("anthropic self-hosted sandboxes disabled due to invalid configuration", "error", err)
		anthropicSelfHostedSandboxesConfig = nil
	}
	if check {
		return nil
	}
	if err := app.SetupLogger(cfg.GetLogging().GetLevel()); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	authenticator, err := controllerAuthenticator(ctx, cfg.GetServer().GetAuth())
	if err != nil {
		return err
	}
	// These downward-API inputs describe this pod, not runtime defaults.
	podTelemetryDefaults(cfg, os.Getenv) //nolint:forbidigo // Private pod identity supplied by Helm.
	options := app.Options{Authenticator: authenticator, AnthropicSelfHostedSandboxes: anthropicSelfHostedSandboxesConfig}
	if err := app.Run(ctx, cfg, options); err != nil {
		slog.Default().ErrorContext(ctx, "controller stopped", "error", err)
		return err
	}
	return nil
}

func controllerAuthenticator(ctx context.Context, cfg *configv1.AuthenticationConfig) (auth.AuthProvider, error) {
	switch cfg.GetMode() {
	case "insecure":
		return &authimpl.InsecureAuthenticator{}, nil
	case "trusted-proxy":
		if len(cfg.GetTrustedIssuers()) == 0 {
			slog.Default().WarnContext(ctx, "trusted-proxy mode decodes bearer JWTs without verifying them; set server.auth.trustedIssuers to verify signatures and audiences")
		}
		client := &http.Client{Timeout: 10 * time.Second}
		issuers := make([]*authimpl.TrustedIssuer, 0, len(cfg.GetTrustedIssuers()))
		for _, trusted := range cfg.GetTrustedIssuers() {
			issuer, err := authimpl.NewTrustedIssuer(ctx, client, trusted.GetIssuer(), trusted.GetAudiences())
			if err != nil {
				return nil, err
			}
			issuers = append(issuers, issuer)
		}
		return authimpl.NewProxyAuthenticator(cfg.GetUserIdClaim(), issuers...), nil
	default:
		return nil, fmt.Errorf("unsupported server.auth.mode %q", cfg.GetMode())
	}
}

func podTelemetryDefaults(cfg *configv1.ControllerConfig, getenv func(string) string) {
	if cfg.Telemetry.ResourceAttributes == nil {
		cfg.Telemetry.ResourceAttributes = map[string]string{}
	}
	for key, value := range map[string]string{
		"k8s.pod.name":        getenv("K8S_POD_NAME"),
		"k8s.pod.uid":         getenv("K8S_POD_UID"),
		"service.instance.id": getenv("K8S_POD_UID"),
		"k8s.node.name":       getenv("K8S_NODE_NAME"),
		"k8s.namespace.name":  cfg.GetKubernetes().GetNamespace(),
		"k8s.container.name":  "controller",
	} {
		if _, set := cfg.Telemetry.ResourceAttributes[key]; !set && value != "" {
			cfg.Telemetry.ResourceAttributes[key] = value
		}
	}
}
