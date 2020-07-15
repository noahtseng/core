// Package sshagent provides the ability to use openssh's ssh-agent
// to carry out key signing operations using keys stored therein.
// This allows ssh keys to be used as Vanadium principals.
package sshagent

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"v.io/v23/security"
	"v.io/x/ref/lib/security/signing"
	"v.io/x/ref/lib/security/signing/internal"
)

// Client represents an ssh-agent client.
type Client struct {
	mu    sync.Mutex
	conn  net.Conn
	agent agent.ExtendedAgent
}

// NewClient returns a new instance of Client.
func NewClient() *Client {
	return &Client{}
}

// NewSigningService returns an implementation of signing.Service that uses
// an ssh-agent to perform signing operations.
func NewSigningService() signing.Service {
	return &Client{}
}

// for testing only.
var sockNameFunc = func() string {
	return os.Getenv("SSH_AUTH_SOCK")
}

func (ac *Client) connect() error {
	ac.mu.Lock()
	if ac.conn != nil && ac.agent != nil {
		ac.mu.Unlock()
		return nil
	}
	ac.mu.Unlock()
	sockName := sockNameFunc()
	conn, err := net.Dial("unix", sockName)
	if err != nil {
		return fmt.Errorf("failed to open %v: %v", sockName, err)
	}
	ac.mu.Lock()
	defer ac.mu.Unlock()
	ac.conn = conn
	ac.agent = agent.NewClient(conn)
	return nil
}
func (ac *Client) Lock(passphrase []byte) error {
	return ac.agent.Lock(passphrase)
}

func (ac *Client) Unlock(passphrase []byte) error {
	return ac.agent.Unlock(passphrase)
}

// Signer implements signing.Service.
func (ac *Client) Signer(ctx context.Context, key string, passphrase []byte) (security.Signer, error) {
	if err := ac.connect(); err != nil {
		return nil, err
	}
	k, err := ac.lookup(key)
	if err != nil {
		return nil, err
	}
	pk, err := ssh.ParsePublicKey(k.Marshal())
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key for %v: %v", key, err)
	}
	var vpk security.PublicKey
	switch pk.Type() {
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		vpk, err = internal.FromECDSAKey(pk)
	case ssh.KeyAlgoED25519:
		vpk, err = internal.FromED25512Key(pk)
	default:
		return nil, fmt.Errorf("unsupported ssh key key tyoe %v", pk.Type())
	}
	if err != nil {
		return nil, err
	}
	return &signer{
		passphrase: passphrase,
		service:    ac,
		sshPK:      pk,
		v23PK:      vpk,
		key:        k,
		name:       key}, nil
}

// Close implements signing.Service.
func (ac *Client) Close(ctx context.Context) error {
	return ac.conn.Close()
}

func (ac *Client) lookup(name string) (*agent.Key, error) {
	keys, err := ac.agent.List()
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		if key.Comment == name {
			if !internal.IsSupported(key) {
				return nil, fmt.Errorf("key %v (%v) is not a supported type", name, key.Type())
			}
			return key, nil
		}
	}
	return nil, fmt.Errorf("key with comment/name %v not found", name)
}

func (ac *Client) ecdsaSign(sshPK ssh.PublicKey, v23PK, purpose, message []byte, name string) (security.Signature, error) {
	digest, digestType, err := internal.DigestsForSSH(sshPK, v23PK, purpose, message)
	if err != nil {
		return security.Signature{}, fmt.Errorf("failed to generate message digesT: %v", err)
	}
	sig, err := ac.agent.Sign(sshPK, digest)
	if err != nil {
		return security.Signature{}, fmt.Errorf("signature operation failed for %v: %v", name, err)
	}
	r, s, err := internal.UnmarshalSSHECDSASignature(sig)
	if err != nil {
		return security.Signature{}, err
	}
	return security.Signature{
		Purpose: purpose,
		Hash:    digestType,
		R:       r,
		S:       s,
	}, nil
}

func (ac *Client) ed25519Sign(sshPK ssh.PublicKey, v23PK, purpose, message []byte, name string) (security.Signature, error) {
	digest, digestType, err := internal.HashedDigestsForSSH(sshPK, v23PK, purpose, message)
	if err != nil {
		return security.Signature{}, fmt.Errorf("failed to generate message digesT: %v", err)
	}
	sig, err := ac.agent.Sign(sshPK, digest)
	if err != nil {
		return security.Signature{}, fmt.Errorf("signature operation failed for %v: %v", name, err)
	}
	return security.Signature{
		Purpose: purpose,
		Hash:    digestType,
		Ed25519: sig.Blob,
	}, nil
}

func (ac *Client) sign(purpose, message []byte, name string, sshPK ssh.PublicKey, v23PK security.PublicKey) (security.Signature, error) {
	keyBytes, err := v23PK.MarshalBinary()
	if err != nil {
		return security.Signature{}, fmt.Errorf("failed to marshal public key: %v", v23PK)
	}
	switch sshPK.Type() {
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		return ac.ecdsaSign(sshPK, keyBytes, purpose, message, name)
	case ssh.KeyAlgoED25519:
		return ac.ed25519Sign(sshPK, keyBytes, purpose, message, name)
	default:
		return security.Signature{}, fmt.Errorf("unsupported key type: %v", sshPK.Type())
	}
}

type signer struct {
	service    *Client
	passphrase []byte
	name       string
	sshPK      ssh.PublicKey
	v23PK      security.PublicKey
	key        *agent.Key
}

// Sign implements security.Signer.
func (sn *signer) Sign(purpose, message []byte) (sig security.Signature, err error) {
	if pw := sn.passphrase; pw != nil {
		if err = sn.service.Unlock(pw); err != nil {
			return
		}
		defer func() {
			nerr := sn.service.Lock(pw)
			if err == nil {
				err = nerr
			}
		}()
	}
	return sn.service.sign(purpose, message, sn.name, sn.sshPK, sn.v23PK)
}

// PublicKey implements security.PublicKey.
func (sn *signer) PublicKey() security.PublicKey {
	return sn.v23PK
}