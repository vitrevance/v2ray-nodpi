//go:build windows

package network

func NewDriverManual(ifaceName, ifaceIP string) (*Driver, error) {
	return nil, newError("windows is not supported")
}

func NewDriver() (*Driver, error) {
	return nil, newError("windows is not supported")
}
