package storage

import (
	"fmt"
	"path"
	"strings"
)

// ArtifactVisibility controls the permissions used when an artifact is
// persisted by a backend.
type ArtifactVisibility uint8

const (
	ArtifactPublic ArtifactVisibility = iota
	ArtifactPrivate
)

// Artifact is a backend-relative generated file.
type Artifact struct {
	Path       string
	Data       []byte
	Visibility ArtifactVisibility
}

// ArtifactStorage stores generated files at fixed backend-relative paths.
type ArtifactStorage interface {
	PutArtifact(artifact Artifact) error
	GetArtifact(name string) (Artifact, error)
	DeleteArtifact(name string) error
}

// ValidateArtifactPath rejects absolute, empty, dot, and traversal paths. The
// portable slash-separated form is used by every backend.
func ValidateArtifactPath(name string) error {
	if name == "" || strings.ContainsRune(name, '\x00') || strings.ContainsAny(name, "\\:") {
		return fmt.Errorf("storage: invalid artifact path %q", name)
	}
	clean := path.Clean(name)
	if clean == "." || clean != name || strings.HasPrefix(clean, "/") || clean == ".." || strings.HasPrefix(clean, "../") {
		return fmt.Errorf("storage: invalid artifact path %q", name)
	}
	return nil
}

// ValidateArtifactVisibility rejects values outside the public contract.
func ValidateArtifactVisibility(visibility ArtifactVisibility) error {
	switch visibility {
	case ArtifactPublic, ArtifactPrivate:
		return nil
	default:
		return fmt.Errorf("storage: invalid artifact visibility %d", visibility)
	}
}
