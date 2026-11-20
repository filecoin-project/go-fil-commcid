package commcid

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"testing"

	//commcid "github.com/filecoin-project/go-fil-commcid"
	commhash "github.com/filecoin-project/go-fil-commp-hashhash"
	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multicodec"
	"github.com/multiformats/go-multihash"
	"github.com/multiformats/go-varint"
	"github.com/stretchr/testify/require"
)

func TestDataCommitmentToCID(t *testing.T) {
	randBytes := make([]byte, 32)
	_, err := rand.Read(randBytes)
	require.NoError(t, err)

	c, err := DataCommitmentV1ToCID(randBytes)
	require.NoError(t, err)

	require.Equal(t, c.Prefix().Codec, uint64(cid.FilCommitmentUnsealed))
	mh := c.Hash()
	decoded, err := multihash.Decode(mh)
	require.NoError(t, err)
	require.Equal(t, decoded.Code, uint64(multihash.SHA2_256_TRUNC254_PADDED))
	require.Equal(t, decoded.Length, len(randBytes))
	require.True(t, bytes.Equal(decoded.Digest, randBytes))
}

func TestCIDToDataCommitment(t *testing.T) {
	randBytes := make([]byte, 32)
	_, err := rand.Read(randBytes)
	require.NoError(t, err)

	t.Run("with correct hash format", func(t *testing.T) {
		hash := testMultiHash(multihash.SHA2_256_TRUNC254_PADDED, randBytes, 0)

		t.Run("decodes raw commitment hash when correct cid format", func(t *testing.T) {
			c := cid.NewCidV1(cid.FilCommitmentUnsealed, hash)
			decoded, err := CIDToDataCommitmentV1(c)
			require.NoError(t, err)
			require.True(t, bytes.Equal(decoded, randBytes))
		})

		t.Run("error on non-fil codec", func(t *testing.T) {
			c := cid.NewCidV1(cid.DagCBOR, hash)
			decoded, err := CIDToDataCommitmentV1(c)
			require.EqualError(t, err, ErrIncorrectCodec.Error())
			require.Nil(t, decoded)
		})

		t.Run("error on wrong fil codec", func(t *testing.T) {
			c := cid.NewCidV1(cid.FilCommitmentSealed, testMultiHash(multihash.POSEIDON_BLS12_381_A1_FC1, randBytes, 0))
			decoded, err := CIDToDataCommitmentV1(c)
			require.EqualError(t, err, ErrIncorrectCodec.Error())
			require.Nil(t, decoded)
		})

		t.Run("error on fil hash/codec mismatch", func(t *testing.T) {
			c := cid.NewCidV1(cid.FilCommitmentUnsealed, testMultiHash(multihash.POSEIDON_BLS12_381_A1_FC1, randBytes, 0))
			decoded, err := CIDToDataCommitmentV1(c)
			require.EqualError(t, err, ErrIncorrectHash.Error())
			require.Nil(t, decoded)
		})

	})

	t.Run("error on incorrectly formatted hash", func(t *testing.T) {
		hash := testMultiHash(multihash.SHA2_256_TRUNC254_PADDED, randBytes, 5)
		c := cid.NewCidV1(cid.FilCommitmentUnsealed, hash)
		decoded, err := CIDToDataCommitmentV1(c)
		require.Error(t, err)
		require.Regexp(t, "^Error decoding data commitment hash:", err.Error())
		require.Nil(t, decoded)
	})
}

func TestReplicaCommitmentToCID(t *testing.T) {
	randBytes := make([]byte, 32)
	_, err := rand.Read(randBytes)
	require.NoError(t, err)

	c, err := ReplicaCommitmentV1ToCID(randBytes)
	require.NoError(t, err)

	require.Equal(t, c.Prefix().Codec, uint64(cid.FilCommitmentSealed))
	mh := c.Hash()
	decoded, err := multihash.Decode([]byte(mh))
	require.NoError(t, err)
	require.Equal(t, decoded.Code, uint64(multihash.POSEIDON_BLS12_381_A1_FC1))
	require.Equal(t, decoded.Length, len(randBytes))
	require.True(t, bytes.Equal(decoded.Digest, randBytes))
}

func TestCIDToReplicaCommitment(t *testing.T) {
	randBytes := make([]byte, 32)
	_, err := rand.Read(randBytes)
	require.NoError(t, err)

	t.Run("with correct hash format", func(t *testing.T) {
		hash := testMultiHash(multihash.POSEIDON_BLS12_381_A1_FC1, randBytes, 0)

		t.Run("decodes raw commitment hash when correct cid format", func(t *testing.T) {
			c := cid.NewCidV1(cid.FilCommitmentSealed, hash)
			decoded, err := CIDToReplicaCommitmentV1(c)
			require.NoError(t, err)
			require.True(t, bytes.Equal(decoded, randBytes))
		})

		t.Run("error on incorrect CID format", func(t *testing.T) {
			c := cid.NewCidV1(cid.DagCBOR, hash)
			decoded, err := CIDToReplicaCommitmentV1(c)
			require.EqualError(t, err, ErrIncorrectCodec.Error())
			require.Nil(t, decoded)
		})

		t.Run("error on non-fil codec", func(t *testing.T) {
			c := cid.NewCidV1(cid.DagCBOR, hash)
			decoded, err := CIDToReplicaCommitmentV1(c)
			require.EqualError(t, err, ErrIncorrectCodec.Error())
			require.Nil(t, decoded)
		})

		t.Run("error on wrong fil codec", func(t *testing.T) {
			c := cid.NewCidV1(cid.FilCommitmentUnsealed, testMultiHash(multihash.SHA2_256_TRUNC254_PADDED, randBytes, 0))
			decoded, err := CIDToReplicaCommitmentV1(c)
			require.EqualError(t, err, ErrIncorrectCodec.Error())
			require.Nil(t, decoded)
		})

		t.Run("error on fil hash/codec mismatch", func(t *testing.T) {
			c := cid.NewCidV1(cid.FilCommitmentSealed, testMultiHash(multihash.SHA2_256_TRUNC254_PADDED, randBytes, 0))
			decoded, err := CIDToReplicaCommitmentV1(c)
			require.EqualError(t, err, ErrIncorrectHash.Error())
			require.Nil(t, decoded)
		})
	})

	t.Run("error on wrong hash type", func(t *testing.T) {
		encoded, err := multihash.Encode(randBytes, multihash.SHA2_256)
		require.NoError(t, err)
		c := cid.NewCidV1(cid.Raw, multihash.Multihash(encoded))
		decoded, err := CIDToReplicaCommitmentV1(c)
		require.EqualError(t, err, ErrIncorrectCodec.Error())
		require.Nil(t, decoded)
	})

	t.Run("error on incorrectly formatted hash", func(t *testing.T) {
		c := cid.NewCidV1(cid.FilCommitmentUnsealed, testMultiHash(multihash.POSEIDON_BLS12_381_A1_FC1, randBytes, 5))
		decoded, err := CIDToReplicaCommitmentV1(c)
		require.Error(t, err)
		require.Regexp(t, "^Error decoding data commitment hash:", err.Error())
		require.Nil(t, decoded)
	})

}

func TestPieceCommitmentToCID(t *testing.T) {
	randBytes := make([]byte, 32)
	_, err := rand.Read(randBytes)
	require.NoError(t, err)

	c, err := PieceCommitmentV1ToCID(randBytes)
	require.NoError(t, err)

	require.Equal(t, c.Prefix().Codec, uint64(cid.FilCommitmentUnsealed))
	mh := c.Hash()
	decoded, err := multihash.Decode([]byte(mh))
	require.NoError(t, err)
	require.Equal(t, decoded.Code, uint64(multihash.SHA2_256_TRUNC254_PADDED))
	require.Equal(t, decoded.Length, len(randBytes))
	require.True(t, bytes.Equal(decoded.Digest, randBytes))

	_, err = PieceCommitmentV1ToCID(randBytes[1:])
	require.Regexp(t, "^commitments must be 32 bytes long", err.Error())
}

func TestCIDToPieceCommitment(t *testing.T) {
	randBytes := make([]byte, 32)
	_, err := rand.Read(randBytes)
	require.NoError(t, err)

	t.Run("with correct hash format", func(t *testing.T) {
		hash := testMultiHash(multihash.SHA2_256_TRUNC254_PADDED, randBytes, 0)

		t.Run("decodes raw commitment hash when correct cid format", func(t *testing.T) {
			c := cid.NewCidV1(cid.FilCommitmentUnsealed, hash)
			decoded, err := CIDToPieceCommitmentV1(c)
			require.NoError(t, err)
			require.True(t, bytes.Equal(decoded, randBytes))
		})

		t.Run("error on incorrect CID format", func(t *testing.T) {
			c := cid.NewCidV1(cid.DagCBOR, hash)
			decoded, err := CIDToPieceCommitmentV1(c)
			require.EqualError(t, err, ErrIncorrectCodec.Error())
			require.Nil(t, decoded)
		})
	})

	t.Run("error on incorrectly formatted hash", func(t *testing.T) {
		hash := testMultiHash(multihash.SHA2_256_TRUNC254_PADDED, randBytes, 5)
		c := cid.NewCidV1(cid.FilCommitmentUnsealed, hash)
		decoded, err := CIDToPieceCommitmentV1(c)
		require.Error(t, err)
		require.Regexp(t, "^Error decoding data commitment hash:", err.Error())
		require.Nil(t, decoded)
	})
	t.Run("error on wrong hash type", func(t *testing.T) {
		encoded, err := multihash.Encode(randBytes, multihash.SHA2_256)
		require.NoError(t, err)
		c := cid.NewCidV1(cid.FilCommitmentUnsealed, multihash.Multihash(encoded))
		decoded, err := CIDToPieceCommitmentV1(c)
		require.EqualError(t, err, ErrIncorrectHash.Error())
		require.Nil(t, decoded)
	})
}

func randomPieceMhInfo(t *testing.T) (treeHeight uint8, paddingSize uint64, dataSize uint64, digest []byte, mhDigest []byte) {
	// CID size = 1 byte tree height + unsigned_varint_data_padding_size (1 to 9 bytes) + 32 byte digest
	// Min/Max size = 34 -> 42
	t.Helper()

	randBytes := make([]byte, 40)
	_, err := rand.Read(randBytes)
	require.NoError(t, err)
	digest = randBytes[0:32]
	dataSize = binary.LittleEndian.Uint64(randBytes[32:])
	// padded dataSize must be less than 2^63 - 1 so we divide by 4 to be safe
	dataSize = dataSize >> 2
	// TODO: at the moment some of the code here requires max size to be 128 times lower
	dataSize = dataSize >> 7
	treeHeight, paddingSize, err = PayloadSizeToV1TreeHeightAndPadding(dataSize)
	require.NoError(t, err)

	uvarintPaddingSize := varint.ToUvarint(paddingSize)
	mhDigest = append(append(uvarintPaddingSize[:], treeHeight), digest...)
	return
}

func TestPieceCommitmentToPieceMhCID(t *testing.T) {
	height, paddingSize, dataSize, digest, _ := randomPieceMhInfo(t)

	c, err := DataCommitmentToPieceCidv2(digest, dataSize)
	require.NoError(t, err)

	require.Equal(t, c.Prefix().Codec, uint64(cid.Raw))
	mh := c.Hash()
	decoded, err := multihash.Decode(mh)
	require.NoError(t, err)
	require.Equal(t, decoded.Code, uint64(multicodec.Fr32Sha256Trunc254Padbintree))
	require.Equal(t, decoded.Length, 1+varint.UvarintSize(paddingSize)+32)
	require.True(t, decoded.Digest[varint.UvarintSize(paddingSize)] == height)

	paddingSizeFromMhDigest, _, err := varint.FromUvarint(decoded.Digest[0:varint.UvarintSize(paddingSize)])
	if err != nil {
		t.Fatal(err)
	}

	require.Equal(t, paddingSize, paddingSizeFromMhDigest)

	_, err = DataCommitmentToPieceCidv2(digest[1:], dataSize)
	require.Regexp(t, "^commitments must be 32 bytes long", err.Error())
}

func TestPieceMhCIDToPieceCommitment(t *testing.T) {
	treeHeight, paddingSize, expectedDataSize, expectedDigest, mhDigest := randomPieceMhInfo(t)

	t.Run("with correct hash format", func(t *testing.T) {
		hash := testMultiHash(uint64(multicodec.Fr32Sha256Trunc254Padbintree), mhDigest, 0)

		t.Run("decodes raw commitment hash when correct cid format", func(t *testing.T) {
			c := cid.NewCidV1(cid.Raw, hash)
			digest, dataSize, err := PieceCidV2ToDataCommitment(c)
			t.Log(treeHeight)
			t.Log(paddingSize)
			require.NoError(t, err)
			require.Equal(t, expectedDataSize, dataSize)
			require.True(t, bytes.Equal(expectedDigest, digest))
		})

		t.Run("don't error on non-Raw CID format", func(t *testing.T) {
			c := cid.NewCidV1(cid.DagCBOR, hash)
			digest, dataSize, err := PieceCidV2ToDataCommitment(c)
			require.NoError(t, err)
			require.Equal(t, expectedDataSize, dataSize)
			require.True(t, bytes.Equal(expectedDigest, digest))
		})
	})

	t.Run("error on incorrectly formatted hash", func(t *testing.T) {
		hash := testMultiHash(uint64(multicodec.Fr32Sha256Trunc254Padbintree), mhDigest, 5)
		c := cid.NewCidV1(cid.Raw, hash)
		digest, _, err := PieceCidV2ToDataCommitment(c)
		require.Error(t, err)
		require.Regexp(t, "^Error decoding data commitment hash:", err.Error())
		require.Nil(t, digest)
	})
	t.Run("error on wrong hash type", func(t *testing.T) {
		encoded, err := multihash.Encode(mhDigest, multihash.SHA2_256)
		require.NoError(t, err)
		c := cid.NewCidV1(cid.Raw, multihash.Multihash(encoded))
		digest, _, err := PieceCidV2ToDataCommitment(c)
		require.EqualError(t, err, ErrIncorrectHash.Error())
		require.Nil(t, digest)
	})
}

func TestTreeHeight(t *testing.T) {
	// Add test fixtures
	noFr32PaddingTests := map[string]struct {
		size    uint64
		height  uint8
		padding int64
	}{
		"127OfEach0-1-2-3":          {127 * 4, 4, 0},
		"512-bytes-should-pad-over": {512, 5, 504},
		"0":                         {0, 2, 127},
		"1":                         {1, 2, 126},
		"31":                        {31, 2, 96},
		"32":                        {32, 2, 95},
		"127":                       {127, 2, 0},
		"32GiB":                     {32 << 30, 31, 33822867456},
		"32GiB-post-padding":        {(32 << 30) * 127 / 128, 30, 0},
		"64GiB":                     {64 << 30, 32, 67645734912},
		"64GiB-post-padding":        {(64 << 30) * 127 / 128, 31, 0},
	}

	for name, tc := range noFr32PaddingTests {
		t.Run(fmt.Sprintf("non-fr32-padding %s", name), func(t *testing.T) {
			t.Run("height-only", func(t *testing.T) {
				height, err := payloadsizeToV1TreeHeight(tc.size)
				require.NoError(t, err)
				require.Equal(t, tc.height, height)
			})
			t.Run("height-and-padding", func(t *testing.T) {
				height, padding, err := PayloadSizeToV1TreeHeightAndPadding(tc.size)
				require.NoError(t, err)
				require.Equal(t, tc.height, height)
				require.Equal(t, uint64(tc.padding), padding)
			})
		})
	}

	// Add test fixtures
	fr32PaddingTests := map[string]struct {
		size   uint64
		height uint8
	}{
		"127OfEach0-1-2-3":              {127 * 4, 4},
		"512-bytes-should-not-pad-over": {512, 4},
		"0":                             {0, 2},
		"1":                             {1, 2},
		"31":                            {31, 2},
		"32":                            {32, 2},
		"127":                           {127, 2},
		"128":                           {128, 2},
		"129":                           {129, 3},
		"32GiB":                         {32 << 30, 30},
		"64GiB":                         {64 << 30, 31},
	}

	for name, tc := range fr32PaddingTests {
		t.Run(fmt.Sprintf("with-fr32-padding %s", name), func(t *testing.T) {
			require.Equal(t, tc.height, fr32PaddedSizeToV1TreeHeight(tc.size))
		})
	}
}

func TestMultihashes(t *testing.T) {
	data127EachOf0_1_2_3 := append(append(append(bytes.Repeat([]byte{0x00}, 127), bytes.Repeat([]byte{0x01}, 127)...), bytes.Repeat([]byte{0x02}, 127)...), bytes.Repeat([]byte{0x03}, 127)...)

	// Add test fixtures
	tests := map[string]struct {
		data     []byte
		v2CidStr string
	}{
		"Empty":                         {[]byte{}, "bafkzcibcp4bdomn3tgwgrh3g532zopskstnbrd2n3sxfqbze7rxt7vqn7veigmy"},
		"1Of1":                          {bytes.Repeat([]byte{0x01}, 1), "bafkzcibcpyba3vw24qoc65kvaeuvst5witskqqwpv6zrniwvsmq6hch6qsq6yly"},
		"64Of1":                         {bytes.Repeat([]byte{0x01}, 64), "bafkzcibch4beda6pru25m2g5kbvsnsj3za7le45vcauwicz2wsmjs43q3dajkpy"},
		"65Of1":                         {bytes.Repeat([]byte{0x01}, 65), "bafkzcibchybkmpf2ifpzvzxjq4hxunlb6hsgyy4tladusdjlvykymhwpdifkkny"},
		"127Of0":                        {bytes.Repeat([]byte{0x00}, 127), "bafkzcibcaabdomn3tgwgrh3g532zopskstnbrd2n3sxfqbze7rxt7vqn7veigmy"},
		"128Of0":                        {bytes.Repeat([]byte{0x00}, 128), "bafkzcibcpybwiktap34inmaex4wbs6cghlq5i2j2yd2bb2zndn5ep7ralzphkdy"},
		"127OfEach0-1-2-3":              {data127EachOf0_1_2_3, "bafkzcibcaaces3nobte6ezpp4wqan2age2s5yxcatzotcvobhgcmv5wi2xh5mbi"},
		"127OfEach0-1-2-3-Then127*4-0s": {append(data127EachOf0_1_2_3[:], bytes.Repeat([]byte{0x00}, 127*4)...), "bafkzcibcaac542av3szurbbscwuu3zjssvfwbpsvbjf6y3tukvlgl2nf5rha6pa"},
		"127OfEach0-1-2-3-Then4-0s":     {append(data127EachOf0_1_2_3[:], bytes.Repeat([]byte{0x00}, 4)...), "bafkzcibd7abqlxticxolgseegik2stpfgkkuwyf6kufex3doorkvmzpjuxwe4dz4"},
		"127OfEach0-1-2-3-Then5-0s":     {append(data127EachOf0_1_2_3[:], bytes.Repeat([]byte{0x00}, 5)...), "bafkzcibd64bqlxticxolgseegik2stpfgkkuwyf6kufex3doorkvmzpjuxwe4dz4"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			v2Cid, err := cid.Parse(tc.v2CidStr)
			require.NoError(t, err)

			h := &commhash.Calc{}
			_, err = h.Write(tc.data)
			if err != nil {
				t.Fatal(err)
			}
			if n := int(commhash.MinPiecePayload) - len(tc.data); n > 0 {
				// Zero padding within the smallest tree leaves the commitment unchanged
				_, err = h.Write(make([]byte, n))
				require.NoError(t, err)
			}
			digest, paddedSize, err := h.Digest()
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("digest: %x", digest)
			t.Logf("unpadded size: %d", len(tc.data))
			t.Logf("padded fr32 data size: %d", paddedSize)

			computedV2Cid, err := DataCommitmentToPieceCidv2(digest, uint64(len(tc.data)))
			require.NoError(t, err)

			cidStr, err := computedV2Cid.StringOfBase(multibase.Base16)
			if err != nil {
				t.Fatal(err)
			}

			c, _, err := PieceCidV1FromV2(computedV2Cid)
			if err != nil {
				t.Fatal(err)
			}

			t.Log(cidStr)
			t.Log(computedV2Cid.String())
			t.Log(c.String())

			require.Equal(t, v2Cid, computedV2Cid)
		})
	}

}

func TestPieceMhCIDValidity(t *testing.T) {
	root := make([]byte, 32)
	tests := map[string]struct {
		padding uint64
		height  uint8
		size    uint64
		err     string
	}{
		"height-1":                {0, 1, 0, "piece CID describes a 64 byte piece, below the 128 byte minimum"},
		"height-2-empty":          {127, 2, 0, ""},
		"height-2-over-capacity":  {128, 2, 0, "piece CID pads 128 bytes, more than the 127 bytes of data a 128 byte piece holds"},
		"height-3-more-than-half": {126, 3, 128, ""},
		"height-3-half":           {127, 3, 0, "piece CID places 127 bytes of data in a 256 byte piece, but data must use the smallest piece that holds it"},
		"height-58":               {0, 58, 127 << 56, ""},
		"height-59":               {0, 59, 0, "piece CID describes a 2^64 byte piece, above the 2^63 byte maximum"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			digest := append(varint.ToUvarint(tc.padding), tc.height)
			digest = append(digest, root...)
			c := cid.NewCidV1(cid.Raw, testMultiHash(uint64(multicodec.Fr32Sha256Trunc254Padbintree), digest, 0))
			_, size, err := PieceCidV2ToDataCommitment(c)
			if tc.err != "" {
				require.EqualError(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.size, size)
		})
	}

	// FRC-0069 invalid test vectors
	for _, s := range []string{
		"bafkzcibd7qbqlxticxolgseegik2stpfgkkuwyf6kufex3doorkvmzpjuxwe4dz4", // 508 bytes at height 5, minimal height is 4
		"bafkzcibcaaa7ljp5iliwuibqe6mo63wtbglzwqyahursbwpq5dvjqmnje5m7wcy",  // height 1
	} {
		t.Run(s, func(t *testing.T) {
			c, err := cid.Parse(s)
			require.NoError(t, err)
			_, _, err = PieceCidV2ToDataCommitment(c)
			require.Error(t, err)
		})
	}
}

func TestPieceMhCIDandV1CIDPieceCommitmentConverters(t *testing.T) {
	_, _, expectedDataSize, expectedDigest, mhDigest := randomPieceMhInfo(t)

	mhv1 := testMultiHash(multihash.SHA2_256_TRUNC254_PADDED, expectedDigest, 0)
	cidv1 := cid.NewCidV1(cid.FilCommitmentUnsealed, mhv1)

	mhv2 := testMultiHash(uint64(multicodec.Fr32Sha256Trunc254Padbintree), mhDigest, 0)
	cidv2 := cid.NewCidV1(cid.Raw, mhv2)

	t.Run("convert v1 piece cid + data size to piece mh cid", func(t *testing.T) {
		c, err := PieceCidV2FromV1(cidv1, expectedDataSize)
		require.NoError(t, err)
		require.Equal(t, cidv2, c)
	})

	t.Run("convert piece mh cid to v1 piece cid + data size", func(t *testing.T) {
		c, dataSize, err := PieceCidV1FromV2(cidv2)
		require.NoError(t, err)
		require.Equal(t, cidv1, c)
		require.Equal(t, expectedDataSize, dataSize)
	})

	// Add test fixtures
	tests := map[string]struct {
		v1CidStr         string
		unpaddedDataSize uint64
		v2CidStr         string
	}{
		"127OfEach0-1-2-3":              {"baga6ea4seaqes3nobte6ezpp4wqan2age2s5yxcatzotcvobhgcmv5wi2xh5mbi", 127 * 4, "bafkzcibcaaces3nobte6ezpp4wqan2age2s5yxcatzotcvobhgcmv5wi2xh5mbi"},
		"empty32GiB":                    {"baga6ea4seaqao7s73y24kcutaosvacpdjgfe5pw76ooefnyqw4ynr3d2y6x2mpq", (32 << 30) * 127 / 128, "bafkzcibcaapao7s73y24kcutaosvacpdjgfe5pw76ooefnyqw4ynr3d2y6x2mpq"},
		"empty64GiB":                    {"baga6ea4seaqomqafu276g53zko4k23xzh4h4uecjwicbmvhsuqi7o4bhthhm4aq", (64 << 30) * 127 / 128, "bafkzcibcaap6mqafu276g53zko4k23xzh4h4uecjwicbmvhsuqi7o4bhthhm4aq"},
		"127OfEach0-1-2-3-Then127*4-0s": {"baga6ea4seaqn42av3szurbbscwuu3zjssvfwbpsvbjf6y3tukvlgl2nf5rha6pa", 127 * 8, "bafkzcibcaac542av3szurbbscwuu3zjssvfwbpsvbjf6y3tukvlgl2nf5rha6pa"},
		"127OfEach0-1-2-3-Then4-0s":     {"baga6ea4seaqn42av3szurbbscwuu3zjssvfwbpsvbjf6y3tukvlgl2nf5rha6pa", 127*4 + 4, "bafkzcibd7abqlxticxolgseegik2stpfgkkuwyf6kufex3doorkvmzpjuxwe4dz4"},
		"127OfEach0-1-2-3-Then5-0s":     {"baga6ea4seaqn42av3szurbbscwuu3zjssvfwbpsvbjf6y3tukvlgl2nf5rha6pa", 127*4 + 5, "bafkzcibd64bqlxticxolgseegik2stpfgkkuwyf6kufex3doorkvmzpjuxwe4dz4"},
	}

	for name, tc := range tests {
		t.Run(fmt.Sprintf("%s-v1-to-v2", name), func(t *testing.T) {
			v1Cid, err := cid.Parse(tc.v1CidStr)
			require.NoError(t, err)

			v2Cid, err := cid.Parse(tc.v2CidStr)
			require.NoError(t, err)

			computedV2Cid, err := PieceCidV2FromV1(v1Cid, tc.unpaddedDataSize)
			require.NoError(t, err)

			require.Equal(t, v2Cid, computedV2Cid)
		})

		t.Run(fmt.Sprintf("%s-v2-to-v1", name), func(t *testing.T) {
			v1Cid, err := cid.Parse(tc.v1CidStr)
			require.NoError(t, err)

			v2Cid, err := cid.Parse(tc.v2CidStr)
			require.NoError(t, err)

			computedV1Cid, computedHeight, err := PieceCidV1FromV2(v2Cid)
			require.NoError(t, err)

			require.Equal(t, v1Cid, computedV1Cid)
			require.Equal(t, tc.unpaddedDataSize, computedHeight)
		})
	}
}

func testMultiHash(code uint64, buf []byte, extra int) multihash.Multihash {
	newBuf := make([]byte, varint.UvarintSize(code)+varint.UvarintSize(uint64(len(buf)))+len(buf)+extra)
	n := varint.PutUvarint(newBuf, code)
	n += varint.PutUvarint(newBuf[n:], uint64(len(buf)))

	copy(newBuf[n:], buf)
	return multihash.Multihash(newBuf)
}
