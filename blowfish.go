// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bcrypt_pbkdf

// This is a modified copy of blowfish package from go.crypto repository.
// Couldn't use the original packages as we need to support salts longer
// than 16 bytes.

type cipher struct {
	p              [18]uint32
	s0, s1, s2, s3 [256]uint32
}

func getWord(data []byte, current *int) uint32 {
	j := *current
	var d uint32
	for k := 0; k < 4; k++ {
		d = d<<8 | uint32(data[j])
		j++
		if j >= len(data) {
			j = 0
		}
	}
	*current = j
	return d
}

func expandKey(key []byte, c *cipher) {
	j := 0
	for i := 0; i < 18; i++ {
		c.p[i] ^= getWord(key, &j)
	}

	var l, r uint32
	for i := 0; i < 18; i += 2 {
		l, r = encryptBlock(l, r, c)
		c.p[i], c.p[i+1] = l, r
	}

	for i := 0; i < 256; i += 2 {
		l, r = encryptBlock(l, r, c)
		c.s0[i], c.s0[i+1] = l, r
	}
	for i := 0; i < 256; i += 2 {
		l, r = encryptBlock(l, r, c)
		c.s1[i], c.s1[i+1] = l, r
	}
	for i := 0; i < 256; i += 2 {
		l, r = encryptBlock(l, r, c)
		c.s2[i], c.s2[i+1] = l, r
	}
	for i := 0; i < 256; i += 2 {
		l, r = encryptBlock(l, r, c)
		c.s3[i], c.s3[i+1] = l, r
	}
}

func expandKeyWithSalt(key, salt []byte, c *cipher) {
	j := 0
	for i := 0; i < 18; i++ {
		c.p[i] ^= getWord(key, &j)
	}
	j = 0
	var l, r uint32
	for i := 0; i < 18; i += 2 {
		l ^= getWord(salt, &j)
		r ^= getWord(salt, &j)
		l, r = encryptBlock(l, r, c)
		c.p[i], c.p[i+1] = l, r
	}
	for i := 0; i < 256; i += 2 {
		l ^= getWord(salt, &j)
		r ^= getWord(salt, &j)
		l, r = encryptBlock(l, r, c)
		c.s0[i], c.s0[i+1] = l, r

	}
	for i := 0; i < 256; i += 2 {
		l ^= getWord(salt, &j)
		r ^= getWord(salt, &j)
		l, r = encryptBlock(l, r, c)
		c.s1[i], c.s1[i+1] = l, r
	}
	for i := 0; i < 256; i += 2 {
		l ^= getWord(salt, &j)
		r ^= getWord(salt, &j)
		l, r = encryptBlock(l, r, c)
		c.s2[i], c.s2[i+1] = l, r
	}
	for i := 0; i < 256; i += 2 {
		l ^= getWord(salt, &j)
		r ^= getWord(salt, &j)
		l, r = encryptBlock(l, r, c)
		c.s3[i], c.s3[i+1] = l, r
	}
}

func encryptBlock(l, r uint32, c *cipher) (uint32, uint32) {
	xl, xr := l, r
	xl ^= c.p[0]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[1]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[2]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[3]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[4]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[5]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[6]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[7]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[8]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[9]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[10]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[11]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[12]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[13]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[14]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[15]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[16]
	xr ^= c.p[17]
	return xr, xl
}

func initCipher(c *cipher) {
	copy(c.p[:], p[:])
	copy(c.s0[:], s0[:])
	copy(c.s1[:], s1[:])
	copy(c.s2[:], s2[:])
	copy(c.s3[:], s3[:])
}
