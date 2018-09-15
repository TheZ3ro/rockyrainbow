package ntlm

// From https://github.com/QMUL/ntlmgen/blob/master/ntlmgen.go
// Also from md5 official Go implementation

import (
	"hash"
	"unsafe"
)

const Size = 16
const BlockSize = -1

func (d *digest) BlockSize() int {
	return int(BlockSize)
}

func (d *digest) Size() int {
	return int(Size)
}

// New returns a new hash.Hash computing the NTLM checksum
func New() hash.Hash {
	d := new(digest)
	d.Reset()
	return d
}

const (
	INIT_A uint32 = 0x67452301
	INIT_B uint32 = 0xefcdab89
	INIT_C uint32 = 0x98badcfe
	INIT_D uint32 = 0x10325476

	SQRT_2 uint32 = 0x5a827999
	SQRT_3 uint32 = 0x6ed9eba1
)

type digest struct {
	output   [4]uint32
	len      uint64
	startKey []byte
}

func (d *digest) Reset() {
	d.output[0] = INIT_A
	d.output[1] = INIT_B
	d.output[2] = INIT_C
	d.output[3] = INIT_D
	d.len = 0
	d.startKey = nil
}
func (d *digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)
	d.startKey = append(d.startKey, p...)
	return
}

func (dig *digest) Sum(buf []byte) []byte {
	if buf != nil {
		dig.Write(buf)
	}

	num_blocks := len(dig.startKey)/32 + 1
	remainder := len(dig.startKey) % 32

	// Hash rounds
	var a uint32
	var b uint32
	var c uint32
	var d uint32

	for ii := 0; ii < num_blocks; ii++ {
		var key string
		var nt_buffer [16]uint32

		a = dig.output[0]
		b = dig.output[1]
		c = dig.output[2]
		d = dig.output[3]

		if ii+1 == num_blocks {
			key = string(dig.startKey[32*ii : 32*ii+remainder])
			nt_buffer[14] = uint32(len(dig.startKey)) << 4
		} else {
			key = string(dig.startKey[32*ii : 32*ii+32])
		}

		length := uint32(len(key))

		var i uint32
		i = 0

		// This looks like little endian utf-16 conversion
		// We should do this better
		for i = 0; i < length/2; i++ {
			nt_buffer[i] = uint32(key[2*i]) | uint32(key[2*i+1])<<16
		}

		if i < 16 {
			if length%2 == 1 {
				nt_buffer[i] = uint32(key[length-1]) | 0x800000
			} else {
				nt_buffer[i] = 0x80
			}
		}

		// Round 1
		a += (d ^ (b & (c ^ d))) + nt_buffer[0]
		a = (a << 3) | (a >> 29)

		d += (c ^ (a & (b ^ c))) + nt_buffer[1]
		d = (d << 7) | (d >> 25)

		c += (b ^ (d & (a ^ b))) + nt_buffer[2]
		c = (c << 11) | (c >> 21)

		b += (a ^ (c & (d ^ a))) + nt_buffer[3]
		b = (b << 19) | (b >> 13)

		a += (d ^ (b & (c ^ d))) + nt_buffer[4]
		a = (a << 3) | (a >> 29)

		d += (c ^ (a & (b ^ c))) + nt_buffer[5]
		d = (d << 7) | (d >> 25)

		c += (b ^ (d & (a ^ b))) + nt_buffer[6]
		c = (c << 11) | (c >> 21)

		b += (a ^ (c & (d ^ a))) + nt_buffer[7]
		b = (b << 19) | (b >> 13)

		a += (d ^ (b & (c ^ d))) + nt_buffer[8]
		a = (a << 3) | (a >> 29)

		d += (c ^ (a & (b ^ c))) + nt_buffer[9]
		d = (d << 7) | (d >> 25)

		c += (b ^ (d & (a ^ b))) + nt_buffer[10]
		c = (c << 11) | (c >> 21)

		b += (a ^ (c & (d ^ a))) + nt_buffer[11]
		b = (b << 19) | (b >> 13)

		a += (d ^ (b & (c ^ d))) + nt_buffer[12]
		a = (a << 3) | (a >> 29)

		d += (c ^ (a & (b ^ c))) + nt_buffer[13]
		d = (d << 7) | (d >> 25)

		c += (b ^ (d & (a ^ b))) + nt_buffer[14]
		c = (c << 11) | (c >> 21)

		b += (a ^ (c & (d ^ a))) + nt_buffer[15]
		b = (b << 19) | (b >> 13)

		// Round 2
		a += ((b & (c | d)) | (c & d)) + nt_buffer[0] + SQRT_2
		a = (a << 3) | (a >> 29)

		d += ((a & (b | c)) | (b & c)) + nt_buffer[4] + SQRT_2
		d = (d << 5) | (d >> 27)

		c += ((d & (a | b)) | (a & b)) + nt_buffer[8] + SQRT_2
		c = (c << 9) | (c >> 23)

		b += ((c & (d | a)) | (d & a)) + nt_buffer[12] + SQRT_2
		b = (b << 13) | (b >> 19)

		a += ((b & (c | d)) | (c & d)) + nt_buffer[1] + SQRT_2
		a = (a << 3) | (a >> 29)

		d += ((a & (b | c)) | (b & c)) + nt_buffer[5] + SQRT_2
		d = (d << 5) | (d >> 27)

		c += ((d & (a | b)) | (a & b)) + nt_buffer[9] + SQRT_2
		c = (c << 9) | (c >> 23)

		b += ((c & (d | a)) | (d & a)) + nt_buffer[13] + SQRT_2
		b = (b << 13) | (b >> 19)

		a += ((b & (c | d)) | (c & d)) + nt_buffer[2] + SQRT_2
		a = (a << 3) | (a >> 29)

		d += ((a & (b | c)) | (b & c)) + nt_buffer[6] + SQRT_2
		d = (d << 5) | (d >> 27)

		c += ((d & (a | b)) | (a & b)) + nt_buffer[10] + SQRT_2
		c = (c << 9) | (c >> 23)

		b += ((c & (d | a)) | (d & a)) + nt_buffer[14] + SQRT_2
		b = (b << 13) | (b >> 19)

		a += ((b & (c | d)) | (c & d)) + nt_buffer[3] + SQRT_2
		a = (a << 3) | (a >> 29)

		d += ((a & (b | c)) | (b & c)) + nt_buffer[7] + SQRT_2
		d = (d << 5) | (d >> 27)

		c += ((d & (a | b)) | (a & b)) + nt_buffer[11] + SQRT_2
		c = (c << 9) | (c >> 23)

		b += ((c & (d | a)) | (d & a)) + nt_buffer[15] + SQRT_2
		b = (b << 13) | (b >> 19)

		// Round 3
		a += (d ^ c ^ b) + nt_buffer[0] + SQRT_3
		a = (a << 3) | (a >> 29)

		d += (c ^ b ^ a) + nt_buffer[8] + SQRT_3
		d = (d << 9) | (d >> 23)

		c += (b ^ a ^ d) + nt_buffer[4] + SQRT_3
		c = (c << 11) | (c >> 21)

		b += (a ^ d ^ c) + nt_buffer[12] + SQRT_3
		b = (b << 15) | (b >> 17)

		a += (d ^ c ^ b) + nt_buffer[2] + SQRT_3
		a = (a << 3) | (a >> 29)

		d += (c ^ b ^ a) + nt_buffer[10] + SQRT_3
		d = (d << 9) | (d >> 23)

		c += (b ^ a ^ d) + nt_buffer[6] + SQRT_3
		c = (c << 11) | (c >> 21)

		b += (a ^ d ^ c) + nt_buffer[14] + SQRT_3
		b = (b << 15) | (b >> 17)

		a += (d ^ c ^ b) + nt_buffer[1] + SQRT_3
		a = (a << 3) | (a >> 29)

		d += (c ^ b ^ a) + nt_buffer[9] + SQRT_3
		d = (d << 9) | (d >> 23)

		c += (b ^ a ^ d) + nt_buffer[5] + SQRT_3
		c = (c << 11) | (c >> 21)

		b += (a ^ d ^ c) + nt_buffer[13] + SQRT_3
		b = (b << 15) | (b >> 17)

		a += (d ^ c ^ b) + nt_buffer[3] + SQRT_3
		a = (a << 3) | (a >> 29)

		d += (c ^ b ^ a) + nt_buffer[11] + SQRT_3
		d = (d << 9) | (d >> 23)

		c += (b ^ a ^ d) + nt_buffer[7] + SQRT_3
		c = (c << 11) | (c >> 21)

		b += (a ^ d ^ c) + nt_buffer[15] + SQRT_3
		b = (b << 15) | (b >> 17)

		dig.output[0] += a
		dig.output[1] += b
		dig.output[2] += c
		dig.output[3] += d
	}

	pf := (*[16]byte)(unsafe.Pointer(&dig.output))[:]

	return pf

}
