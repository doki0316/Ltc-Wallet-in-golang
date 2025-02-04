package main

import (
	"crypto/sha256"
	"fmt"
	"log"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/ripemd160"
)

// Wallet represents a wallet containing a private key and public key
type Wallet struct {
	PrivateKey *secp256k1.PrivateKey
	PublicKey  []byte
}

// NewWallet generates a new wallet with a private key and compressed public key
func NewWallet() *Wallet {
	privKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		log.Panic(err)
	}
	pubKey := privKey.PubKey().SerializeCompressed() // Ensure public key is compressed
	return &Wallet{PrivateKey: privKey, PublicKey: pubKey}
}

// GetLegacyAddress generates a Legacy P2PKH Litecoin address
func (w *Wallet) GetLegacyAddress() string {
	pubKeyHash := hashPubKey(w.PublicKey)

	// Litecoin's P2PKH prefix: 0x30 for mainnet
	versionedPayload := append([]byte{0x30}, pubKeyHash...)

	// Add checksum
	checksum := checksum(versionedPayload)

	// Create full address
	fullPayload := append(versionedPayload, checksum...)
	return base58Encode(fullPayload)
}

// privateKeyToWIF converts a private key to compressed WIF format for Litecoin
func privateKeyToWIF(privateKey *secp256k1.PrivateKey) string {
	rawKey := privateKey.Serialize()

	// Add Litecoin WIF prefix (0xB0 for Litecoin mainnet)
	extendedKey := append([]byte{0xB0}, rawKey...)

	// Append 0x01 to indicate compressed private key
	extendedKey = append(extendedKey, 0x01)

	// Calculate checksum
	firstHash := sha256.Sum256(extendedKey)
	secondHash := sha256.Sum256(firstHash[:])
	checksum := secondHash[:4]

	// Base58 encode
	finalKey := append(extendedKey, checksum...)
	return base58Encode(finalKey)
}

// hashPubKey performs SHA256 followed by RIPEMD160 hashing on a public key
func hashPubKey(pubKey []byte) []byte {
	pubHash := sha256.Sum256(pubKey)
	ripemdHasher := ripemd160.New()
	_, err := ripemdHasher.Write(pubHash[:])
	if err != nil {
		log.Panic(err)
	}
	return ripemdHasher.Sum(nil)
}

// checksum creates a 4-byte checksum from a payload
func checksum(payload []byte) []byte {
	firstHash := sha256.Sum256(payload)
	secondHash := sha256.Sum256(firstHash[:])
	return secondHash[:4]
}

// base58Encode encodes a byte slice into Base58
func base58Encode(input []byte) string {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	result := []byte{}
	x := new(big.Int).SetBytes(input)
	radix := big.NewInt(58)
	mod := new(big.Int)

	for x.Cmp(big.NewInt(0)) > 0 {
		x.DivMod(x, radix, mod)
		result = append(result, alphabet[mod.Int64()])
	}

	// Reverse the result
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	// Add leading zeroes
	for _, b := range input {
		if b != 0 {
			break
		}
		result = append([]byte{'1'}, result...)
	}

	return string(result)
}

// electrumKeyFormat adds a script type prefix (e.g., "p2pkh") to a WIF private key for Electrum
func electrumKeyFormat(wifKey, scriptType string) string {
	return fmt.Sprintf("%s:%s", scriptType, wifKey)
}

// main demonstrates generating and formatting an Electrum-compatible private key
func main() {
	// Generate a new wallet
	wallet := NewWallet()

	// Convert private key to WIF
	wifKey := privateKeyToWIF(wallet.PrivateKey)

	// Generate Electrum-compatible formats
	p2pkhKey := electrumKeyFormat(wifKey, "p2pkh")            // Legacy (starts with "L")
	p2wpkhKey := electrumKeyFormat(wifKey, "p2wpkh")          // Native SegWit (starts with "ltc1")
	p2wpkhP2shKey := electrumKeyFormat(wifKey, "p2wpkh-p2sh") // SegWit Wrapped in P2SH (starts with "3")

	// Print keys
	fmt.Println("Litecoin Electrum Private Keys:")
	fmt.Println("Legacy (P2PKH):", p2pkhKey)
	fmt.Println("Native SegWit (P2WPKH):", p2wpkhKey)
	fmt.Println("SegWit (P2SH-P2WPKH):", p2wpkhP2shKey)

	// Print Litecoin address (Legacy)
	address := wallet.GetLegacyAddress()
	fmt.Println("Litecoin Address (Legacy):", address)
}
