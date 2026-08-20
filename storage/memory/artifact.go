package memory

import "github.com/kemsta/go-easyrsa/v2/storage"

// ArtifactStorage stores generated artifacts in memory.
type ArtifactStorage struct{ s *store }

func (a *ArtifactStorage) PutArtifact(artifact storage.Artifact) error {
	if err := storage.ValidateArtifactPath(artifact.Path); err != nil {
		return err
	}
	if err := storage.ValidateArtifactVisibility(artifact.Visibility); err != nil {
		return err
	}
	a.s.mu.Lock()
	defer a.s.mu.Unlock()
	a.s.artifacts[artifact.Path] = cloneArtifact(artifact)
	return nil
}

func (a *ArtifactStorage) GetArtifact(name string) (storage.Artifact, error) {
	if err := storage.ValidateArtifactPath(name); err != nil {
		return storage.Artifact{}, err
	}
	a.s.mu.RLock()
	defer a.s.mu.RUnlock()
	artifact, ok := a.s.artifacts[name]
	if !ok {
		return storage.Artifact{}, storage.ErrNotFound
	}
	return cloneArtifact(artifact), nil
}

func (a *ArtifactStorage) DeleteArtifact(name string) error {
	if err := storage.ValidateArtifactPath(name); err != nil {
		return err
	}
	a.s.mu.Lock()
	defer a.s.mu.Unlock()
	if _, ok := a.s.artifacts[name]; !ok {
		return storage.ErrNotFound
	}
	delete(a.s.artifacts, name)
	return nil
}

var _ storage.ArtifactStorage = (*ArtifactStorage)(nil)
