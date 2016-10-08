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
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
)

var step int64 = 30
var epoch int64 = 0

func Totp(k []byte, t int64, h func() hash.Hash, l int64) (string, error) {

	if l > 9 || l < 1 {
		return "", errors.New("Totp: Length out of range.")
	}

	time := new(bytes.Buffer)

	err := binary.Write(time, binary.BigEndian, (t-epoch)/step)
	if err != nil {
		return "", err
	}

	hash := hmac.New(h, k)
	hash.Write(time.Bytes())
	v := hash.Sum(nil)

	o := v[len(v)-1] & 0xf
	c := (int32(v[o]&0x7f)<<24 | int32(v[o+1])<<16 | int32(v[o+2])<<8 | int32(v[o+3])) % 1000000000

	return fmt.Sprintf("%010d", c)[10-l : 10], nil
}
