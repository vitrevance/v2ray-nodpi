package syncmap

import "sync"

type SyncMap[K comparable, V any] struct {
	m sync.Map
}

func (m *SyncMap[K, V]) CompareAndDelete(key K, old V) (deleted bool) {
	return m.m.CompareAndDelete(key, old)
}
func (m *SyncMap[K, V]) CompareAndSwap(key K, old V, new V) bool {
	return m.m.CompareAndSwap(key, old, new)
}
func (m *SyncMap[K, V]) Delete(key K) {
	m.m.Delete(key)
}
func (m *SyncMap[K, V]) Load(key K) (value V, ok bool) {
	v, ok := m.m.Load(key)
	return v.(V), ok
}
func (m *SyncMap[K, V]) LoadAndDelete(key K) (value V, loaded bool) {
	v, ok := m.m.LoadAndDelete(key)
	return v.(V), ok
}
func (m *SyncMap[K, V]) LoadOrStore(key K, value V) (actual V, loaded bool) {
	a, ok := m.m.LoadOrStore(key, value)
	return a.(V), ok
}
func (m *SyncMap[K, V]) Range(f func(key K, value V) bool) {
	m.m.Range(func(key, value any) bool {
		return f(key.(K), value.(V))
	})
}
func (m *SyncMap[K, V]) Store(key K, value V) {
	m.m.Store(key, value)
}
func (m *SyncMap[K, V]) Swap(key K, value V) (previous V, loaded bool) {
	p, l := m.m.Swap(key, value)
	return p.(V), l
}
