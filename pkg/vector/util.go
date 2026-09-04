package vector

import (
	"github.com/google/uuid"
)

// NewUUID generates a string UUID for Qdrant points.
func NewUUID() string {
	return uuid.New().String()
}
