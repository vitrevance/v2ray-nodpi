package gensync

import "sync"

type Map[K comparable, V any] struct {
	m sync.Map
}

func (m *Map[K, V]) CompareAndDelete(key K, old V) (deleted bool) {
	return m.m.CompareAndDelete(key, old)
}
func (m *Map[K, V]) CompareAndSwap(key K, old V, new V) bool {
	return m.m.CompareAndSwap(key, old, new)
}
func (m *Map[K, V]) Delete(key K) {
	m.m.Delete(key)
}
func (m *Map[K, V]) Load(key K) (value V, ok bool) {
	var v any
	v, ok = m.m.Load(key)
	if v != nil {
		value = v.(V)
	}
	return
}
func (m *Map[K, V]) LoadAndDelete(key K) (value V, loaded bool) {
	var v any
	v, loaded = m.m.LoadAndDelete(key)
	if v != nil {
		value = v.(V)
	}
	return
}
func (m *Map[K, V]) LoadOrStore(key K, value V) (actual V, loaded bool) {
	var v any
	v, loaded = m.m.LoadOrStore(key, value)
	if v != nil {
		actual = v.(V)
	}
	return
}
func (m *Map[K, V]) Range(f func(key K, value V) bool) {
	m.m.Range(func(key, value any) bool {
		return f(key.(K), value.(V))
	})
}
func (m *Map[K, V]) Store(key K, value V) {
	m.m.Store(key, value)
}
func (m *Map[K, V]) Swap(key K, value V) (previous V, loaded bool) {
	var v any
	v, loaded = m.m.Swap(key, value)
	if v != nil {
		previous = v.(V)
	}
	return
}
