package main


import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"time"
)


const p_key = "af1de9a9cb32fb77d430842b5feb46f75733c49e803a0717b6507f2caa5732d4b3cf2f1d5d61ab7cf1e82cadc16c1632351f966ce764a7763b91608e2fc9a80f0b1c88bd23462091f9b91c9dc039238527de71b96b3551f59255b5c5b40532e2327014fac8f3d2f48919d114df9b1a96217e455baf422538be883a469414b81d"

func Reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}


func enc(login string, pwd string, ier string) string {
	t := time.Now().UnixNano() / int64(time.Millisecond)
	var publicKey rsa.PublicKey
	publicKey.N, _ = new(big.Int).SetString(p_key, 16)
	publicKey.E = 65537
	var plain_text, encrypted []byte
	plain_text = []byte(fmt.Sprintf("%s|%d|%v", login, t%1000, pwd))
	/*label := []byte("")
	hash := sha1.New()
	encrypted, err := rsa.EncryptOAEP(hash, rand.Reader, &publicKey, plain_text, label)*/
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, &publicKey, plain_text)
	dst := make([]byte, hex.EncodedLen(len(encrypted)))
	hex.Encode(dst, encrypted)
	if err != nil {
		fmt.Println(err)
	}
	return fmt.Sprintf("l=%d&d=%s&p=%v", t, url.QueryEscape(Reverse(ier)), string(dst))

}


func main() {
	fmt.Println("Server started on :11588 port")
	http.HandleFunc("/gen", func(w http.ResponseWriter, r *http.Request) {
		result := enc(r.URL.Query()["login"][0], r.URL.Query()["pwd"][0], r.URL.Query()["ier"][0])
		fmt.Fprintf(w, "%s", result)
	})
	http.ListenAndServe(":11588", nil)
}
