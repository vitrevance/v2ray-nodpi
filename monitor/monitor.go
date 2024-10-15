package monitor

import (
	"context"

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
}

func NewMonitor(ctx context.Context, config *Config) (*Monitor, error) {
	m := &Monitor{}

	m.config = config
	return m, nil
}

func (m *Monitor) Start() error {
	return nil
}

func (m *Monitor) Close() error {

	return nil
}

func (m *Monitor) Type() any {
	return (*Monitor)(nil)
}
