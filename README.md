# jugugu-open
 jugugu开源钱包
# conflux-sdk-private
  包含了树图conflux区块链SDK修改版；以太坊ethreumSDK修改版；主要修改了私钥部分
# conflux-server
  区块链交易处理和半密钥存储
# jugugu-sdk
  提供可用jugugu测试网服务例子程序，可以直接通过git 该例子程序完成区块链账户地址生成与区块链交互
  ## SDK 函数详情请参考我的GitHub
  ##  https://github.com/doxulovezh/blockchaincommon-go-sdk
  `
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

	// 注册账户
	cfx, eth, err := bcc.Reg(bcc.TestIPandPort, bcc.ERC测试项目AAPID, "!!qinchuan@NFT", "Reg")
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println(cfx, eth)
	}
 }
  
 `
# pice-server
  秒分片存储服务（单服务器模式）
