package jwtmiddleware

import "testing"

var d, _ = NewBadgerDBStore(".")
func TestDefaultStore_Put(t *testing.T) {
	key := "testBearerToken"
	if err := d.Put(key); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultStore_Revoke(t *testing.T) {
	key := "testBearerToken"
	if err := d.Revoke(key); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultStore_Revoked(t *testing.T) {
	key := "NotRevokedTestBearerToken"
	if revoked := d.Revoked(key); !revoked {
		t.Fatal("key should not 've been revoked because it does not exists yet")
	}
}

func TestAll(t *testing.T) {
	d, err := NewBadgerDBStore("db")
	if err != nil {
		t.Fatal(err)
	}
	key := "Bearer Token"
	if err := d.Put(key); err != nil {
		t.Fatal(err)
	}
	revoked := d.Revoked(key)
	if revoked {
		t.Fatal("key should not 've been revoked")
	}
	if err := d.Revoke(key); err != nil {
		t.Fatal(err)
	}
	if revoked := d.Revoked(key); !revoked {
		t.Fatal("key should've been revoked")
	}
}
