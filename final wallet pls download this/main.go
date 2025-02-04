package main

import (
	"crypto/sha256"
	"fmt"
	"fyne.io/fyne/v2/canvas"
	"log"
	"math/big"
	"os"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/ripemd160"
)

// Wallet represents a Litecoin wallet containing a private key and public key
type Wallet struct {
	PrivateKey *secp256k1.PrivateKey
	PublicKey  []byte
}

// NewWallet generates a new wallet with a compressed public key
func NewWallet() *Wallet {
	privKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		log.Panic(err)
	}
	// Compressed public key
	pubKey := privKey.PubKey().SerializeCompressed()
	return &Wallet{PrivateKey: privKey, PublicKey: pubKey}
}

// GetLegacyAddress generates a Legacy P2PKH Litecoin address
func (w *Wallet) GetLegacyAddress() string {
	pubKeyHash := hashPubKey(w.PublicKey)

	// Litecoin P2PKH prefix: 0x30 for mainnet
	versionedPayload := append([]byte{0x30}, pubKeyHash...)

	// Add checksum
	checksum := checksum(versionedPayload)

	// Construct full Litecoin address
	fullPayload := append(versionedPayload, checksum...)
	return base58Encode(fullPayload)
}

// privateKeyToWIF converts a private key to Litecoin WIF (compressed)
func privateKeyToWIF(privateKey *secp256k1.PrivateKey) string {
	rawKey := privateKey.Serialize()

	// Add Litecoin WIF prefix (0xB0 for mainnet)
	extendedKey := append([]byte{0xB0}, rawKey...)

	// Append 0x01 to indicate compressed private key
	extendedKey = append(extendedKey, 0x01)

	// Add checksum
	firstHash := sha256.Sum256(extendedKey)
	secondHash := sha256.Sum256(firstHash[:])
	checksum := secondHash[:4]

	// Base58 encode
	finalKey := append(extendedKey, checksum...)
	return base58Encode(finalKey)
}

// electrumKeyFormat adds a script type prefix (e.g., "p2pkh") to a WIF private key
func electrumKeyFormat(wifKey, scriptType string) string {
	return fmt.Sprintf("%s:%s", scriptType, wifKey)
}

// hashPubKey performs SHA256 followed by RIPEMD160 hashing on the public key
func hashPubKey(pubKey []byte) []byte {
	pubHash := sha256.Sum256(pubKey)
	ripemdHasher := ripemd160.New()
	_, err := ripemdHasher.Write(pubHash[:])
	if err != nil {
		log.Panic(err)
	}
	return ripemdHasher.Sum(nil)
}

// checksum generates a 4-byte checksum
func checksum(payload []byte) []byte {
	firstHash := sha256.Sum256(payload)
	secondHash := sha256.Sum256(firstHash[:])
	return secondHash[:4]
}

// base58Encode encodes a byte slice into Base58 encoding
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

	// Add leading zeroes for leading zero bytes in the input
	for _, b := range input {
		if b != 0 {
			break
		}
		result = append([]byte{'1'}, result...)
	}

	return string(result)
}

// Create the Fyne-based GUI
func main() {
	// Create Fyne application
	myApp := app.New()
	myWindow := myApp.NewWindow("Litecoin Wallet Generator")

	// Create labels for private key and address
	privateKeyLabel := widget.NewLabel("Private Key (Electrum-Format):")
	privateKeyValue := widget.NewLabel("")

	publicKeyLabel := widget.NewLabel("LTC Address:")
	publicKeyValue := widget.NewLabel("")

	// Button to generate wallet
	generateButton := widget.NewButton("Generate Wallet", func() {
		// Generate a new wallet
		wallet := NewWallet()

		// Convert private key to WIF
		wifKey := privateKeyToWIF(wallet.PrivateKey)

		// Generate Electrum-compatible keys
		p2pkhKey := electrumKeyFormat(wifKey, "p2pkh")            // Legacy P2PKH
		p2wpkhKey := electrumKeyFormat(wifKey, "p2wpkh")          // Native SegWit
		p2wpkhP2shKey := electrumKeyFormat(wifKey, "p2wpkh-p2sh") // SegWit in P2SH

		// Set Legacy (P2PKH) key as default display
		privateKeyValue.SetText(fmt.Sprintf("P2PKH: %s\nP2WPKH: %s\nP2WPKH-P2SH: %s", p2pkhKey, p2wpkhKey, p2wpkhP2shKey))

		// Display Litecoin address (Legacy)
		publicKeyValue.SetText(wallet.GetLegacyAddress())
	})

	// Button to save wallet to an HTML file
	saveButton := widget.NewButton("Save to HTML", func() {
		privateKey := privateKeyValue.Text
		if privateKey == "" {
			dialog.ShowInformation("Error", "Please generate a wallet first!", myWindow)
			return
		}

		// Save wallet information to an HTML file
		fileContent := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
	<title>Litecoin Wallet</title>
</head>
<body>
	<h1>Your Litecoin Wallet</h1>
	<pre>%s</pre>
	<p><strong>Address:</strong> %s</p>
</body>
</html>`, privateKey, publicKeyValue.Text)

		file, err := os.Create("litecoin_wallet.html")
		if err != nil {
			dialog.ShowError(err, myWindow)
			return
		}
		defer file.Close()

		_, err = file.WriteString(fileContent)
		if err != nil {
			dialog.ShowError(err, myWindow)
			return
		}

		dialog.ShowInformation("Success", "Wallet saved to litecoin_wallet.html", myWindow)
	})

	// Button to display QR Code
	qrButton := widget.NewButton("Show QR Code", func() {
		privateKey := privateKeyValue.Text
		if privateKey == "" {
			dialog.ShowInformation("Error", "Please generate a wallet first!", myWindow)
			return
		}

		// Generate QR code image for the private key
		qrCodeFile := "private_key_qr.png"
		err := qrcode.WriteFile(privateKey, qrcode.Medium, 256, qrCodeFile)
		if err != nil {
			dialog.ShowError(err, myWindow)
			return
		}

		// Display QR code image
		img := canvas.NewImageFromFile(qrCodeFile)
		dialog.ShowCustom("QR Code", "Close", img, myWindow)
	})

	// Layout
	content := container.NewVBox(
		privateKeyLabel, privateKeyValue,
		publicKeyLabel, publicKeyValue,
		generateButton, saveButton, qrButton,
	)

	myWindow.SetContent(content)
	myWindow.Resize(fyne.NewSize(500, 450))
	myWindow.ShowAndRun()
}
