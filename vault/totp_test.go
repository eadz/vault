// https://github.com/JonLundy/Totp.go
// The MIT License (MIT)
//
// Copyright (c) 2014 JonLundy
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package vault

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"hash"
	"testing"
	"time"
)

var key string = "KR5IFRJE7N7NFHH3"

func TestTotpAuth(t *testing.T) {
	k, _ := base32.StdEncoding.DecodeString(key)

	totp, _ := Totp(k, time.Now().Unix(), sha1.New, 6)
	t.Logf("AUTH Key: %s TOTP:%s", key, totp)
}

func TestTotpLength(t *testing.T) {
	k, _ := base32.StdEncoding.DecodeString(key)

	for i := int64(1); i < 10; i++ {
		totp, err := Totp(k, time.Now().Unix(), sha1.New, i)
		if err != nil {
			t.Error(err)
		}
		if int64(len(totp)) != i {
			t.Error("Length not equal: ", i)
		}
	}
}

func TestTotpVectors(t *testing.T) {
	for _, v := range testvectors {
		totp, err := Totp(genkey(v.l), v.t, v.h, 8)
		if err != nil {
			t.Error(err)
		}
		if totp != v.s {
			t.Error("Wrong Code Generation: Expect:", v.s, " Got: ", totp)
		}
	}
}

func genkey(l int64) []byte {
	s := make([]byte, l)

	for i := int64(0); i < l; i++ {
		s[i] = byte((i+1)%10 + 48)
	}
	return s
}

type testvector struct {
	l int64
	t int64
	h func() hash.Hash
	s string
}

var testvectors []testvector = []testvector{{20, 59, sha1.New, "94287082"},
	{32, 59, sha256.New, "46119246"},
	{64, 59, sha512.New, "90693936"},
	{20, 1111111109, sha1.New, "07081804"},
	{32, 1111111109, sha256.New, "68084774"},
	{64, 1111111109, sha512.New, "25091201"},
	{20, 1111111111, sha1.New, "14050471"},
	{32, 1111111111, sha256.New, "67062674"},
	{64, 1111111111, sha512.New, "99943326"},
	{20, 1234567890, sha1.New, "89005924"},
	{32, 1234567890, sha256.New, "91819424"},
	{64, 1234567890, sha512.New, "93441116"},
	{20, 2000000000, sha1.New, "69279037"},
	{32, 2000000000, sha256.New, "90698825"},
	{64, 2000000000, sha512.New, "38618901"},
	{20, 20000000000, sha1.New, "65353130"},
	{32, 20000000000, sha256.New, "77737706"},
	{64, 20000000000, sha512.New, "47863826"}}
