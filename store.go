package jwtmiddleware

import (
	"errors"
	"github.com/dgraph-io/badger"
)
// JwtStorer abstracts storage for revocable JWTs
type JwtStorer interface {
	// Put stores a JWT token in the underlined storage implementation.
	Put(key string) error
	// Revoke revokes a JWT token, this should be done when a logout
	// action is triggered by the user
	Revoke(key string) error
	// Revoked check if key/token has been revoked or does not exists.
	// returns true if token has been revoked or false otherwise
	Revoked(key string) bool
}

// ErrRevoked is returned by `jwtmiddleware.CheckJWT()` when the token being
// checked has been revoked by `store.Revoke()` call
var ErrRevoked = errors.New("JWT token has been revoked")

type badgerDbStore struct {
	db *badger.DB
}

// newDefaultStore creates a badgerDB backed JWT store
func NewBadgerDBStore(dbDir string) (*badgerDbStore, error) {
	opt := badger.DefaultOptions(dbDir)
	db, err := badger.Open(opt)
	if err != nil {
		return nil, err
	}
	return &badgerDbStore{db: db}, nil
}

func (d *badgerDbStore) Put(key string) error {
	return d.db.Update(func(txn *badger.Txn) error {
		value := []byte(nil)
		return txn.Set([]byte(key), value)
	})
}

func (d *badgerDbStore) Revoke(key string) error {
	return d.db.Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte(key))
	})
}

func (d *badgerDbStore) Revoked(key string) bool {
	err := d.db.View(func(txn *badger.Txn) error {
		_, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}
		return nil
	})
	if err == badger.ErrKeyNotFound {
		return true
	}
	return false
}