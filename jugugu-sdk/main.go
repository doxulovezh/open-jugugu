package main

// https://github.com/doxulovezh/blockchaincommon-go-sdk
/*
 * @Descripttion:封装密钥托管的引用例子；文档请Follow Link      https://pkg.go.dev/github.com/doxulovezh/blockchaincommon-go-sdk
 * @version:0.1
 * @Author: 秦风大哥
 * @Date: 2022-01-21 17:58:30
 * @LastEditors: 秦风大哥
 * @LastEditTime: 2022-01-21 18:04:46
 */

import (
	"fmt"

	bcc "github.com/doxulovezh/blockchaincommon-go-sdk"
)

var body []byte

func main() {
	err := bcc.InitRSAPuk("globlepublic.pem", "Returnprivate.pem")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	cfx, eth, err := bcc.RegByPrivateKey(bcc.TestIPandPort, bcc.ERC测试项目AAPID, "我擦1234567890", "8708ff69b5bb3383d3ae79996ce2ef81832b6570785644645cc356cb7a4e335d", "RegByPrivateKey")
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println(cfx, eth)
	}
	// 多次批量创建NFT(-1)
	// cfx, eth, err := bcc.Reg(bcc.TestIPandPort, bcc.ERC测试项目AAPID, "!!qinchuan@NFT", "Reg")
	// if err != nil {
	// 	fmt.Println(err.Error())
	// } else {
	// 	fmt.Println(cfx, eth)
	// }
	// fmt.Println(acc.SHA256_strReturnString("123456"))
	PrvKey, err := bcc.GetPrivateKey(bcc.TestIPandPort, bcc.ERC测试项目AAPID, "我擦1234567890", "cfxtest:aat0mupj008e71urzc72pgrnhdc5sv590a08r4ts8v", "GetPrivateKey")
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println(string(PrvKey))
	}

	// body, err := bcc.UserNFTURIPost(bcc.TestIPandPort, "CFX_TokenUri", bcc.ERC测试项目AAPID, "1", "CFX_TokenUri", "cfxs")
	// if err != nil {
	// 	fmt.Println(err.Error())
	// } else {
	// 	fmt.Println(string(body))
	// }
	// // 多次批量创建NFT(-1)
	// var tos []string
	// tos = append(tos, bcc.TestCFXAdministratorAddress)
	// tos = append(tos, bcc.TestCFXAdministratorAddress)
	// tos = append(tos, bcc.TestCFXAdministratorAddress)
	// tos = append(tos, bcc.TestCFXAdministratorAddress)
	// tos = append(tos, bcc.TestCFXAdministratorAddress)
	// tos = append(tos, bcc.TestCFXAdministratorAddress)
	// body, err = bcc.AdminCreateNFTBatchPost(bcc.TestIPandPort, "CFX_AdminCreateNFTBatch", bcc.ERC测试项目AAPID, -1, 50000, bcc.TestAdministratorPassword, bcc.TestCFXAdministratorAddress, tos, "CFX_AdminCreateNFTBatch", "cfx")
	// if err != nil {
	// 	panic(err)
	// } else {
	// 	fmt.Println(string(body))
	// }
	// //转移
	// body, err = bcc.TransferFromPost(bcc.TestIPandPort, "CFX_TransferFrom", bcc.ERC测试项目AAPID, -1, 5000, bcc.TestAdministratorPassword, bcc.TestCFXAdministratorAddress, bcc.TestCFXAdministratorAddress, "6", "", "cfx")
	// if err != nil {
	// 	panic(err)
	// } else {
	// 	fmt.Println(string(body))
	// }
	// body, err := bcc.AdminCreateNFTPost(bcc.TestIPandPort, "CFX_AdminCreateNFT", bcc.ERC测试项目AAPID, -1, 5000, bcc.TestAdministratorPassword, bcc.TestCFXAdministratorAddress, bcc.TestCFXAdministratorAddress, "", "cfx")
	// if err != nil {
	// 	panic(err)
	// } else {
	// 	fmt.Println(string(body))
	// }

	// //批量转移
	// var tos []string
	// tos = append(tos, bcc.TestCFXAdministratorAddress)
	// tos = append(tos, bcc.TestCFXAdministratorAddress)
	// tos = append(tos, bcc.TestCFXAdministratorAddress)
	// tos = append(tos, bcc.TestCFXAdministratorAddress)
	// tos = append(tos, bcc.TestCFXAdministratorAddress)
	// tos = append(tos, bcc.TestCFXAdministratorAddress)
	// var ids []string
	// ids = append(ids, "469")
	// ids = append(ids, "470")
	// ids = append(ids, "471")
	// ids = append(ids, "472")
	// ids = append(ids, "473")
	// ids = append(ids, "474")
	// body, err := bcc.AdminTransferNFTBatchPost(bcc.TestIPandPort, "CFX_AdminTransferNFTBatch", bcc.ERC测试项目AAPID, -1, 50000, bcc.TestAdministratorPassword, bcc.TestCFXAdministratorAddress, tos, ids, "CFX_AdminTransferNFTBatch", "cfx")
	// if err != nil {
	// 	panic(err)
	// } else {
	// 	fmt.Println(string(body))
	// }
}

func 多次批量创建NFT(i int64) {
	var tos []string
	tos = append(tos, bcc.TestCFXAdministratorAddress)
	tos = append(tos, bcc.TestCFXAdministratorAddress)
	tos = append(tos, bcc.TestCFXAdministratorAddress)
	tos = append(tos, bcc.TestCFXAdministratorAddress)
	body, err := bcc.AdminCreateNFTBatchPost(bcc.TestIPandPort, "CFX_AdminCreateNFTBatch", bcc.ERC测试项目AAPID, i, 50000,
		bcc.TestAdministratorPassword, bcc.TestCFXAdministratorAddress, tos, "CFX_AdminCreateNFTBatch", "cfx")
	if err != nil {
		panic(err)
	} else {
		fmt.Println(string(body))
	}
	// var ids []string
	// ids = append(ids, "409")
	// ids = append(ids, "410")
	// ids = append(ids, "411")
	// ids = append(ids, "412")
	// //1155转移请将action设置为：CFX_1155TransferFrom
	// //721转移请将action设置为：CFX_TransferFrom
	// body, err := bcc.AdminTransferNFTBatchPost(bcc.TestIPandPort, "CFX_AdminTransferNFTBatch", bcc.ERC测试项目AAPID, -1, 50000,
	// 	bcc.TestAdministratorPassword, bcc.TestCFXAdministratorAddress, tos, ids, "CFX_AdminTransferNFTBatch", "cfx")
	// if err != nil {
	// 	panic(err)
	// } else {
	// 	fmt.Println(string(body))
	// }
}
