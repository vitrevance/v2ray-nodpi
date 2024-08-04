package v4

import (
	"github.com/golang/protobuf/proto"
	"github.com/v2fly/v2ray-core/v5/proxy/nodpi"
)

type NodpiConfig struct {
}

func (l NodpiConfig) Build() (proto.Message, error) {
	return &nodpi.Config{}, nil
}
