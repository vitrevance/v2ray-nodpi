package monitor

import (
	"context"
	"fmt"

	"github.com/labstack/echo"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/v2fly/v2ray-core/v5/common"
)

//go:generate protoc --go_out=.. --go_opt=paths=source_relative -I .. monitor/config.proto

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config any) (any, error) {
		return NewMonitor(ctx, config.(*Config))
	}))
}

type Monitor struct {
	config *Config
	server *echo.Echo
}

func NewMonitor(ctx context.Context, config *Config) (*Monitor, error) {
	m := &Monitor{}
	m.server = echo.New()
	m.server.GET("/metrics", echo.WrapHandler(promhttp.Handler()))
	m.config = config
	return m, nil
}

func (m *Monitor) Start() error {
	go m.server.Start(fmt.Sprintf("0.0.0.0:%d", m.config.GetPort()))
	return nil
}

func (m *Monitor) Close() error {
	m.server.Shutdown(context.Background())
	return nil
}

func (m *Monitor) Type() any {
	return (*Monitor)(nil)
}
