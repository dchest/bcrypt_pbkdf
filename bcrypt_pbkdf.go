// Copyright 2014 Dmitry Chestnykh. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package bcrypt_pbkdf implements password-based key derivation function based
// on bcrypt compatible with bcrypt_pbkdf(3) from OpenBSD.
package bcrypt_pbkdf

import (
	"crypto/sha512"
	"errors"
)

// Key derives a key from the password, salt and rounds count, returning a
// []byte of length keyLen that can be used as cryptographic key.
//
// Remember to get a good random salt of at least 16 bytes.  Using a higher
// rounds count will increase the cost of an exhaustive search but will also
// make derivation proportionally slower.
func Key(password, salt []byte, rounds, keyLen int) ([]byte, error) {
	if rounds < 1 {
		return nil, errors.New("bcrypt_pbkdf: number of rounds is too small")
	}
	if len(password) == 0 {
		return nil, errors.New("bcrypt_pbkdf: empty password")
	}
	if len(salt) == 0 || len(salt) > 1<<20 {
		return nil, errors.New("bcrypt_pbkdf: bad salt length")
	}
	if keyLen > 1024 {
		return nil, errors.New("bcrypt_pbkdf: keyLen is too large")
	}
	var shapass, shasalt [sha512.Size]byte
	var out, tmp [32]byte
	var cnt [4]byte

	numBlocks := (keyLen + len(out) - 1) / len(out)
	key := make([]byte, numBlocks*len(out))

	h := sha512.New()
	h.Write(password)
	h.Sum(shapass[:0])

	for block := 1; block <= numBlocks; block++ {
		h.Reset()
		h.Write(salt)
		cnt[0] = byte(block >> 24)
		cnt[1] = byte(block >> 16)
		cnt[2] = byte(block >> 8)
		cnt[3] = byte(block)
		h.Write(cnt[:])
		bcryptHash(tmp[:], shapass[:], h.Sum(shasalt[:0]))
		copy(out[:], tmp[:])

		for i := 2; i <= rounds; i++ {
			h.Reset()
			h.Write(tmp[:])
			bcryptHash(tmp[:], shapass[:], h.Sum(shasalt[:0]))
			for j := 0; j < len(out); j++ {
				out[j] ^= tmp[j]
			}
		}

		for i, v := range out {
			key[i*numBlocks+(block-1)] = v
		}
	}
	return key[:keyLen], nil
}

var magic = []byte("OxychromaticBlowfishSwatDynamite")

func bcryptHash(out, shapass, shasalt []byte) {
	var c cipher
	initCipher(&c)
	expandKeyWithSalt(shapass, shasalt, &c)
	for i := 0; i < 64; i++ {
		expandKey(shasalt, &c)
		expandKey(shapass, &c)
	}
	var ct [8]uint32
	j := 0
	for i := range ct {
		ct[i] = getWord(magic, &j)
	}
	for i := 0; i < 8; i += 2 {
		l, r := ct[i], ct[i+1]
		for j := 0; j < 64; j++ {
			l, r = encryptBlock(l, r, &c)
		}
		ct[i], ct[i+1] = l, r
	}
	for i, v := range ct {
		out[4*i+3] = byte(v >> 24)
		out[4*i+2] = byte(v >> 16)
		out[4*i+1] = byte(v >> 8)
		out[4*i+0] = byte(v)
	}
}
