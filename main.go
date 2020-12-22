package main

import (
	"AES_base64/aes_base64"
	"fmt"
)

func main() {
	pass := "mypassword"
	xpass := aes_base64.AesEncrypt(pass)

	fmt.Printf("加密后:%v\n", xpass)

	tpass := aes_base64.AesDecrypt(xpass)
	if pass == tpass {
		fmt.Println("加解密成功！")
	} else {
		fmt.Println("加解密失败！")
	}
}
