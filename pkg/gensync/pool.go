package gensync

import "sync"

type Pool[T any] sync.Pool

func (p *Pool[T]) Get() T {
	return (*sync.Pool)(p).Get().(T)
}
func (p *Pool[T]) Put(v T) {
	(*sync.Pool)(p).Put(v)
}
