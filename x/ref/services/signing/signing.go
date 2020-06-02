// Package signing provides support for various external signing 'services'.
// Such services can be used to provide Vanadium principals that exist
// outside of Vanadium. For example, a signing service is provided
// use ssh keys via ssh-agent to sign requests.
package signing

import (
	"context"

	"v.io/v23/security"
)

// Service defines the interface for a signing service.
type Service interface {
	// Signer returns a security.Signer for the specified key.
	Signer(ctx context.Context, keyName string) (security.Signer, security.PublicKey, error)
	// Close releases/closes all resources associated with the service instance.
	Close(ctx context.Context) error
}
