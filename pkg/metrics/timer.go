package metrics

import "time"

type Timer struct {
	start time.Time
	total time.Duration
	min   time.Duration
	max   time.Duration
	count int
}

func (t *Timer) Start() {
	t.start = time.Now()
}

func (t *Timer) Stop() {
	elapsed := time.Now().Sub(t.start)
	t.total += elapsed
	t.count++
	t.min = min(t.min, elapsed)
	t.max = max(t.max, elapsed)
}

func (t *Timer) Iters() int {
	return t.count
}
func (t *Timer) Avg() time.Duration {
	return t.total / time.Duration(t.count)
}
func (t *Timer) Min() time.Duration {
	return t.min
}
func (t *Timer) Max() time.Duration {
	return t.max
}
func (t *Timer) Total() time.Duration {
	return t.total
}
