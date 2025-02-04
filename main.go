package main

import (
	"crypto/sha256"
	"fmt"
	"log"
	"math/big"
	"os"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/ripemd160"
)

// Wallet 表示私钥和公钥配对
type Wallet struct {
	PrivateKey *secp256k1.PrivateKey
	PublicKey  []byte
}

// NewWallet 创建一个新的钱包
func NewWallet() *Wallet {
	privKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		log.Panic(err)
	}
	pubKey := privKey.PubKey().SerializeCompressed()
	return &Wallet{PrivateKey: privKey, PublicKey: pubKey}
}

// GetAddress 生成莱特币地址
func (w *Wallet) GetAddress() string {
	pubKeyHash := hashPubKey(w.PublicKey)
	versionedPayload := append([]byte{0x30}, pubKeyHash...) // 使用莱特币主网前缀 0x30
	checksum := checksum(versionedPayload)
	fullPayload := append(versionedPayload, checksum...)
	return base58Encode(fullPayload)
}

// hashPubKey 对公钥进行双哈希处理
func hashPubKey(pubKey []byte) []byte {
	pubHash := sha256.Sum256(pubKey)
	ripemdHasher := ripemd160.New()
	_, err := ripemdHasher.Write(pubHash[:])
	if err != nil {
		log.Panic(err)
	}
	return ripemdHasher.Sum(nil)
}

// checksum 生成校验和
func checksum(payload []byte) []byte {
	firstHash := sha256.Sum256(payload)
	secondHash := sha256.Sum256(firstHash[:])
	return secondHash[:4]
}

// base58Encode Base58 编码
func base58Encode(input []byte) string {
	const encodeAlphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	result := []byte{}
	x := new(big.Int).SetBytes(input)
	radix := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)

	for x.Cmp(zero) != 0 {
		x.DivMod(x, radix, mod)
		result = append(result, encodeAlphabet[mod.Int64()])
	}

	// 反转结果
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return string(result)
}

func main() {
	// 创建 Fyne 应用
	myApp := app.New()
	myWindow := myApp.NewWindow("LTC Wallet Generator")

	// 创建用于显示私钥和地址的文本框
	privateKeyLabel := widget.NewLabel("Private Key:")
	privateKeyValue := widget.NewLabel("")

	publicKeyLabel := widget.NewLabel("LTC Address:")
	publicKeyValue := widget.NewLabel("")

	// 生成钱包按钮
	generateButton := widget.NewButton("Generate Wallet", func() {
		wallet := NewWallet()
		privateKeyValue.SetText(fmt.Sprintf("%x", wallet.PrivateKey.Serialize()))
		publicKeyValue.SetText(wallet.GetAddress())
	})

	// 保存按钮
	saveButton := widget.NewButton("Save to HTML", func() {
		privateKey := privateKeyValue.Text
		publicKey := publicKeyValue.Text

		// 检查是否生成了钱包
		if privateKey == "" || publicKey == "" {
			// 使用弹窗显示提示信息
			dialog.ShowInformation("Error", "Please generate a wallet first!", myWindow)
			return
		}

		// 生成 HTML 文件并保存
		fileContent := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <title>LTC Wallet</title>
</head>
<body>
    <h1>Your Litecoin Wallet</h1>
    <p><strong>Private Key:</strong> %s</p>
    <p><strong>LTC Address:</strong> %s</p>
</body>
</html>`, privateKey, publicKey)

		file, err := os.Create("wallet.html")
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

		dialog.ShowInformation("Success", "Wallet saved to wallet.html", myWindow)
	})

	// 布局
	content := container.NewVBox(
		privateKeyLabel, privateKeyValue,
		publicKeyLabel, publicKeyValue,
		generateButton, saveButton,
	)

	myWindow.SetContent(content)
	myWindow.Resize(fyne.NewSize(400, 300))
	myWindow.ShowAndRun()
}
