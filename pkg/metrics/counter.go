package metrics

import "sync/atomic"

type Counter struct {
	count uint32
}

func (c *Counter) Add(v uint32) uint32 {
	return atomic.AddUint32(&c.count, v)
}

func (c *Counter) Count() uint32 {
	return atomic.LoadUint32(&c.count)
}

func (c *Counter) Reset() uint32 {
	return atomic.SwapUint32(&c.count, 0)
}
