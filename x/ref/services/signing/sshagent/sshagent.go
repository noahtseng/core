// Package sshagent provides the ability to use openssh's ssh-agent
// to carry out key signing operations using keys stored therein.
// This allows ssh keys to be used as Vanadium principals.
package sshagent

import (
	"context"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"v.io/v23/security"
	"v.io/x/ref/services/signing"
	"v.io/x/ref/services/signing/internal"
)

type service struct {
	mu    sync.Mutex
	conn  net.Conn
	agent agent.ExtendedAgent
}

func NewService() signing.Service {
	return &service{}
}

var sockNameFunc = func() string {
	return os.Getenv("SSH_AUTH_SOCK")
}

func (s *service) connect() error {
	s.mu.Lock()
	if s.conn != nil && s.agent != nil {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()
	sockName := sockNameFunc()
	conn, err := net.Dial("unix", sockName)
	if err != nil {
		return fmt.Errorf("failed to open %v: %v", sockName, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conn = conn
	s.agent = agent.NewClient(conn)
	return nil
}

// Signer implements signing.Service.
func (s *service) Signer(ctx context.Context, key string) (security.Signer, security.PublicKey, error) {
	if err := s.connect(); err != nil {
		return nil, nil, err
	}
	k, err := s.lookup(key)
	if err != nil {
		return nil, nil, err
	}
	pk, err := ssh.ParsePublicKey(k.Marshal())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse public key for %v: %v", key, err)
	}
	vpk, err := internal.V23PublicKey(pk)
	if err != nil {
		return nil, nil, err
	}
	return &signer{
		service: s,
		sshPK:   pk,
		v23PK:   vpk,
		key:     k,
		name:    key}, vpk, nil
}

// Close implements signing.Service.
func (s *service) Close(ctx context.Context) error {
	return s.conn.Close()
}

func (s *service) lookup(name string) (*agent.Key, error) {
	keys, err := s.agent.List()
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		if key.Comment == name {
			if !internal.IsSupported(key) {
				return nil, fmt.Errorf("key %v is not of a supported type", name)
			}
			return key, nil
		}
	}
	return nil, fmt.Errorf("key with comment/name %v not found", name)
}

func (s *service) sign(purpose, message []byte, name string, sshPK ssh.PublicKey, v23PK security.PublicKey) (security.Signature, error) {
	digest, digestType, err := internal.MessageForSSH(sshPK, v23PK, purpose, message)
	if err != nil {
		return security.Signature{}, fmt.Errorf("failed to generate message digesT: %v", err)
	}
	sig, err := s.agent.Sign(sshPK, digest)
	if err != nil {
		return security.Signature{}, fmt.Errorf("signature operation failed for %v: %v", name, err)
	}
	var ecSig struct {
		R, S *big.Int
	}
	err = ssh.Unmarshal(sig.Blob, &ecSig)
	if err != nil {
		return security.Signature{}, fmt.Errorf("failed to unmarshal signature: %v", err)
	}
	return security.Signature{
		Purpose: purpose,
		Hash:    digestType,
		R:       ecSig.R.Bytes(),
		S:       ecSig.S.Bytes(),
	}, nil
}

type signer struct {
	service *service
	name    string
	sshPK   ssh.PublicKey
	v23PK   security.PublicKey
	key     *agent.Key
}

// Sign implements security.Signer.
func (sn *signer) Sign(purpose, message []byte) (security.Signature, error) {
	return sn.service.sign(purpose, message, sn.name, sn.sshPK, sn.v23PK)
}

// PublicKey implements security.PublicKey.
func (sn *signer) PublicKey() security.PublicKey {
	return nil
}
