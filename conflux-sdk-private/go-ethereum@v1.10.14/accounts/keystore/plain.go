// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package keystore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
)

type keyStorePlain struct {
	keysDirPath string
}

func (ks keyStorePlain) GetKeytikverse(addr common.Address, privakeyhash string) (*Key, error) {
	// Load the key from the keystore and decrypt its contents
	//decode
	// var mt = "0xf4601a7e5b982a9c4221a6a83f3df389729c141ccdd12200c5cbed588313967e"
	// data := mt
	// hdata := calculateHashcode(data)
	// fmt.Println("信息串：", data)
	// fmt.Println("sha256加密后：", hdata)
	// bdata := []byte(hdata)
	// fmt.Println("auth", auth)
	// prk, err := crypto.HexToECDSA(auth) //"265e130a42371e7a3f7cf2a5d93c8bc9b4e24b6903260e4765b751850959ec76"
	// if err != nil {
	// 	panic(err)
	// }
	// // prk, err := getKey(auth)
	// prk2 := ecies.ImportECDSA(prk)
	// // puk2 := prk2.PublicKey
	// // fmt.Println(hex.EncodeToString(crypto.FromECDSA(prk)))
	// // priKey, err := crypto.HexToECDSA(priKeyHash)
	// // endata, err := ECCEncrypt([]byte(bdata), puk2)
	// // if err != nil {
	// // 	panic(err)
	// // }
	// // fmt.Println("ecc公钥加密后：", hex.EncodeToString(EnCodeStrHEX))
	// buffer, err := hex.DecodeString(EnCodeStrHEX)
	// if err != nil {
	// 	panic(err)
	// }
	// dedata, err := ECCDecrypt(buffer, *prk2)
	// if err != nil {
	// 	fmt.Println("DecodeString")
	// 	panic(err)
	// }
	// fmt.Println("私钥解密：", string(dedata))

	// //
	// var privakeyhash = string(dedata)
	key, err := DecryptKey_DX(privakeyhash)
	if err != nil {
		return nil, err
	}
	privakeyhash = ""
	// dedata = nil
	// Make sure we're really operating on the requested key (no swap attacks)
	// fmt.Println("key.Address", key.Address)
	// fmt.Println("addr", addr)
	// if key.Address != addr {
	// 	return nil, fmt.Errorf("key content mismatch: have account %x, want %x", key.Address, addr)
	// }
	// fmt.Println("棋逢对手 passphrase.go")
	return key, nil
}
func DecryptKey_DX(priKeyHash string) (*Key, error) {
	// Parse the json into a simple map to fetch the key version
	//dx  改成priKey, err := crypto.HexToECDSA(priKeyHash)
	priKey, err := crypto.HexToECDSA(priKeyHash)
	id := uuid.UUID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	if err != nil {
		return nil, err
	}
	CAD := crypto.PubkeyToAddress(priKey.PublicKey)
	buff := []byte(CAD.String())
	buff[2] = 49
	Newcfxaddr := common.HexToAddress(string(buff))
	// fmt.Println("Newcfxaddr", Newcfxaddr.String())
	return &Key{
		Id:         id,
		Address:    Newcfxaddr,
		PrivateKey: priKey,
	}, nil
}

func (ks keyStorePlain) GetKey(addr common.Address, filename, auth string) (*Key, error) {
	fd, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	key := new(Key)
	if err := json.NewDecoder(fd).Decode(key); err != nil {
		return nil, err
	}
	if key.Address != addr {
		return nil, fmt.Errorf("key content mismatch: have address %x, want %x", key.Address, addr)
	}
	return key, nil
}

func (ks keyStorePlain) StoreKey(filename string, key *Key, auth string) error {
	content, err := json.Marshal(key)
	if err != nil {
		return err
	}
	return writeKeyFile(filename, content)
}

func (ks keyStorePlain) JoinPath(filename string) string {
	if filepath.IsAbs(filename) {
		return filename
	}
	return filepath.Join(ks.keysDirPath, filename)
}
