package pki

import (
	"errors"

	"github.com/kemsta/go-easyrsa/v2/storage"
)

func (p *PKI) bound() bool { return p != nil && p.storage != nil }

func (p *PKI) bind(components storage.Components) *PKI {
	bound := *p
	bound.components = components
	bound.storage = components.Keys()
	bound.csrStorage = components.CSRs()
	bound.index = components.Index()
	bound.serial = components.Serials()
	bound.crlHolder = components.CRLs()
	bound.artifacts = components.Artifacts()
	bound.lifecycle = components.Lifecycle()
	return &bound
}

func withView[T any](p *PKI, fn func(*PKI) (T, error)) (result T, err error) {
	if p == nil || p.backend == nil {
		return result, errors.New("pki: storage backend is required")
	}
	err = p.backend.View(func(components storage.Components) error {
		result, err = fn(p.bind(components))
		return err
	})
	return result, err
}

func withUpdate[T any](p *PKI, fn func(*PKI) (T, error)) (result T, err error) {
	if p == nil || p.backend == nil {
		return result, errors.New("pki: storage backend is required")
	}
	err = p.backend.Update(func(components storage.Components) error {
		result, err = fn(p.bind(components))
		return err
	})
	return result, err
}

func withViewError(p *PKI, fn func(*PKI) error) error {
	_, err := withView(p, func(bound *PKI) (struct{}, error) {
		return struct{}{}, fn(bound)
	})
	return err
}

func withUpdateError(p *PKI, fn func(*PKI) error) error {
	_, err := withUpdate(p, func(bound *PKI) (struct{}, error) {
		return struct{}{}, fn(bound)
	})
	return err
}
