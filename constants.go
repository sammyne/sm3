package sm3

// The blocksize of SM3 in bytes.
const BlockSize = 64

// The size of a SM3 checksum in bytes.
const Size = 32

const (
	chunk = 64
	iv0   = 0x7380166f
	iv1   = 0x4914b2b9
	iv2   = 0x172442d7
	iv3   = 0xda8a0600
	iv4   = 0xa96f30bc
	iv5   = 0x163138aa
	iv6   = 0xe38dee4d
	iv7   = 0xb0fb0e4e

	t0 = 0x79cc4519
	t1 = 0x7a879d8a
)
