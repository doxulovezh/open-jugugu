package main

import (
	"fmt"

	bcc "github.com/doxulovezh/blockchaincommon-go-sdk"
)

func main() {
	err := bcc.InitRSAPuk("globlepublic.pem", "Returnprivate.pem")
	if err != nil {
		panic(err)
	}
	//注册
	cfxaddr, ethaddr, err := bcc.Reg(bcc.TestIPandPort, bcc.ERC测试项目AAPID, "pass123", "Reg")
	if err != nil {
		panic(err)
	}
	fmt.Println(cfxaddr, ethaddr)
	fmt.Println("----------------------------------------------------")

	//NFT创建
	var TOS []string
	TOS = append(TOS, bcc.TestCFXAdministratorAddress)
	TOS = append(TOS, bcc.TestCFXAdministratorAddress)
	hash, err := bcc.AdminCreateNFTBatchPost(bcc.TestIPandPort, "CFX_AdminCreateNFTBatch", bcc.ERC测试项目AAPID, -1, 5000,
		bcc.TestAdministratorPassword, bcc.TestCFXAdministratorAddress, TOS, "CFX_AdminCreateNFTBatch", "cfx")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(hash))
	fmt.Println("----------------------------------------------------")

	//NFT转移（已经发售）
	var IDS []string
	IDS = append(IDS, "1842")
	IDS = append(IDS, "1843") //与地址数组一一对应
	hash, err = bcc.AdminTransferNFTBatchPost(bcc.TestIPandPort, "CFX_AdminTransferNFTBatch", bcc.ERC测试项目AAPID, -1, 5000,
		bcc.TestAdministratorPassword, bcc.TestCFXAdministratorAddress, TOS, IDS, "CFX_AdminTransferNFTBatch", "cfx")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(hash))

}
