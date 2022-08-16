package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"
	acc "web/util"

	"github.com/Conflux-Chain/go-conflux-sdk/types/cfxaddress"
	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/middleware/logger"
	"github.com/patrickmn/go-cache"

	sdk "github.com/Conflux-Chain/go-conflux-sdk"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/ethclient"
	_ "github.com/go-sql-driver/mysql"
	IrisRecover "github.com/kataras/iris/v12/middleware/recover"
)

var GetCFXDataCatch *cache.Cache
var GetETHDataCatch *cache.Cache
var GloKS *keystore.KeyStore
var (
	DB       *sql.DB
	GlobalDB *sql.DB
)
var wg sync.WaitGroup

var APPID_PrvKeyPiceServer string = "0x123456" //小红花
var PUK *rsa.PublicKey
var PUKReturn *rsa.PublicKey

// var APPID1 string = "0xd67c8aed16df25b21055993449222fa895c67eb87bb1d7130c38cc469d8625b5" //小红花
var IPandPort string = "https://127.0.0.1:13143" //http://127.0.0.1:13145
// 妥善管理员密码保管
var ADMIN_PASSWORD string = "123456"
var app *iris.Application

var APPIDdict map[string]string                          //定义dict为map类型
var ProjectNamedict map[string]string                    //定义dict为map类型
var ProjectPublickeyCatchdict map[string]*rsa.PrivateKey //定义dict为map类型
var ContractAddressMap map[string]common.Address         //定义dict为map类型
var Tokencatch *cache.Cache                              //令牌缓存
var Noncecatch *cache.Cache                              //区块链交易Nonce缓存
var prk22 *ecies.PrivateKey
var puk22 ecies.PublicKey
var UserRegitStm *sql.Stmt
var SELECTAddressStm *sql.Stmt
var SELECTETHAddressStm *sql.Stmt
var ALL_SELECTAddressStm *sql.Stmt
var Gpassword string = ""

type setting struct {
	ServerIP     string `json:"serverIP"`
	ServerPort   string `json:"serverPort"`
	CFXNetid     uint32 `json:"cfxnetid"`
	CFXNodeURL   string `json:"cfxnodeURL"`
	ETHNetid     uint32 `json:"ethnetid"`
	ETHNodeURL   string `json:"ethnodeURL"`
	BSCNetid     uint32 `json:"bscnetid"`
	BSCNodeURL   string `json:"bscnodeURL"`
	ARBNetid     uint32 `json:"arbnetid"`
	ARBNodeURL   string `json:"arbnodeURL"`
	CSUATNetid   uint32 `json:"csuatnetid"`
	CSUATNodeURL string `json:"csuatnodeURL"`

	IPandPort string `json:"ipandport"`
	RSA       string `json:"rsa"`
}
type Prvhalfdata_Message struct {
	Sha256Value []byte `json:"sha256value"`
	Appid       []byte `json:"appid"`
	Time        []byte `json:"emit"`
	Token       []byte `json:"token"`
	Address     []byte `json:"address"`
	ETHAddress  []byte `json:"ethaddress"`
	Data        []byte `json:"data"`
}

var (
	ServerIP       string
	ServerPort     string
	privatekeyname string
	publickeyname  string
	APPID          string
	CFXNetID       uint32
	CFXNodeURL     string
	ETHNetID       uint32
	ETHNodeURL     string
	BSCNetID       uint32
	BSCNodeURL     string
	ARBNetID       uint32
	ARBNodeURL     string
	CSUATNetID     uint32
	CSUATNodeURL   string
	RASModel       string
	cfxclientRPC   *sdk.Client
	cfxclient2RPC  *sdk.Client
	ethclientRPC   *ethclient.Client
	bscclientRPC   *ethclient.Client
	arbclientRPC   *ethclient.Client
	csuatclientRPC *ethclient.Client
)

type KeyData_Message struct {
	key  string
	data string
}

var HalfPrvDataPostclient *http.Client

func todayFilename() string {
	today := time.Now().Format("Jan 02 2006")
	return today + ".txt"
}

func newLogFile() *os.File {
	filename := "./log/" + todayFilename()
	// Open the file, this will append to the today's file if server restarted.
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		panic(err)
	}
	return f
}

// 初始化Key data 至内存
func InitCFXKeyDataCatch() {
	fmt.Println("开始缓存")
	var NUM uint64 = 0
	var res *sql.Rows
	var err error
	var Dat string
	var Key string
	var cfxaddress string
	var ethaddress string
	res, err = ALL_SELECTAddressStm.Query()
	if err != nil {
		panic(err)
	}
	defer res.Close()
	for res.Next() {
		NUM++
		res.Scan(&Dat, &Key, &cfxaddress, &ethaddress)
		//AES 解ECC
		var KD KeyData_Message
		KD.data = Dat
		KD.key = Key
		GetCFXDataCatch.Set(cfxaddress, KD, cache.NoExpiration)
		GetETHDataCatch.Set(ethaddress, KD, cache.NoExpiration)
	}
	fmt.Println("Success Init KeyData Catch!", NUM)
	app.Logger().Info("Success Init KeyData Catch!", NUM)
}

// 错误处理
func PanicHandler() {
	exeName := os.Args[0]                                             //获取程序名称
	now := time.Now()                                                 //获取当前时间
	pid := os.Getpid()                                                //获取进程ID
	time_str := now.Format("20060102150405")                          //设定时间格式
	fname := fmt.Sprintf("%s-%d-%s-dump.log", exeName, pid, time_str) //保存错误信息文件名:程序名-进程ID-当前时间（年月日时分秒）
	fmt.Println("dump to file", fname)
	f, err := os.Create(fname)
	if err != nil {
		return
	}
	defer f.Close()
	if err := recover(); err != nil {
		f.WriteString(fmt.Sprintf("%v\r\n", err)) //输出panic信息
		f.WriteString("========\r\n")
	}
	f.WriteString(string(debug.Stack())) //输出堆栈信息
}
func main() {
	defer PanicHandler()
	SQLInit() //数据库初始化
	StmInit() //数据库初始化
	initClient()
	PicePUKInit()   //分片服务器公钥初始化
	ReturnPukInit() //返回值加密
	// 创建一个cache对象，默认ttl 5分钟，每10分钟对过期数据进行一次清理
	Tokencatch = cache.New(5*time.Minute, 5*time.Minute)
	//缓存Key dat
	GetCFXDataCatch = cache.New(cache.NoExpiration, cache.NoExpiration)
	GetETHDataCatch = cache.New(cache.NoExpiration, cache.NoExpiration)
	InitServerSetting() //区块链服务器相关初始化
	//预先初始化
	ProjectKeysInitPrew()
	ProjectKeysInit() //项目RSA私钥初始化
	//https
	app = iris.New()
	app.Logger().SetLevel("debug")
	//设置recover从panics恢复，设置log记录
	app.Use(logger.New())
	app.Use(IrisRecover.New())
	//初始化缓存
	InitCFXKeyDataCatch()
	app.Get("/text", text)
	app.Post("/UserRegit", UserRegit)
	app.Post("/CFX_TotalSupply", CFX_TotalSupply)
	app.Post("/CFX_AdminCreateNFT", CFX_AdminCreateNFT)
	app.Post("/CFX_AdminCreateNFTBatch", CFX_AdminCreateNFTBatch)
	app.Post("/CFX_AdminCreateNFTBatch_URI", CFX_AdminCreateNFTBatch_URI)
	app.Post("/CFX_AdminTransferNFTBatch", CFX_AdminTransferNFTBatch)
	app.Post("/CFX_TransferFrom", CFX_TransferFrom)
	app.Post("/CFX_UserNFTs", CFX_UserNFTs)
	app.Post("/CFX_TokenUri", CFX_TokenUri)
	app.Post("/CFX_OwnerOf", CFX_OwnerOf)
	app.Post("/CFX_ApproveForAll", CFX_ApproveForAll)
	app.Post("/CFX_IsApproveForAll", CFX_IsApproveForAll)
	app.Post("/CFX_Burn", CFX_Burn)
	//WETH
	app.Post("/ETH_TotalSupply", ETH_TotalSupply)
	app.Post("/ETH_AdminCreateNFT", ETH_AdminCreateNFT)
	app.Post("/ETH_AdminCreateNFTBatch", ETH_AdminCreateNFTBatch)
	app.Post("/ETH_AdminTransferNFTBatch", ETH_AdminTransferNFTBatch)
	app.Post("/ETH_TransferFrom", ETH_TransferFrom)

	app.Post("/ETH_Burn", ETH_Burn)
	app.Post("/ETH_Approve", ETH_Approve)
	app.Post("/ETH_UserNFTs", ETH_UserNFTs)
	app.Post("/ETH_BurnBatch", ETH_BurnBatch)
	app.Post("/ETH_TokenUri", ETH_TokenUri)
	app.Post("/ETH_OwnerOf", ETH_OwnerOf)
	app.Post("/ETH_ApproveForAll", ETH_ApproveForAll)
	//特殊同步账号
	app.Post("/UserRegitByPrivateKey", UserRegitByPrivateKey)
	//setData
	app.Post("/FSCSetData", CFX_FSC_SetData)
	//ERC1155
	app.Post("/CFX_1155TotalSupply", CFX_1155TotalSupply)
	app.Post("/CFX_1155TotalAmount", CFX_1155TotalAmount)
	app.Post("/CFX_1155BalanceOf", CFX_1155BalanceOf)
	app.Post("/CFX_1155BalanceOfBatch", CFX_1155BalanceOfBatch)
	app.Post("/CFX_1155AdminCreateNFT", CFX_1155AdminCreateNFT)
	app.Post("/CFX_1155AdminCreateNFTBatch", CFX_1155AdminCreateNFTBatch)
	app.Post("/CFX_1155AdminSafeTransferNFTBatch", CFX_1155AdminSafeTransferNFTBatch)
	app.Post("/CFX_1155SafeTransferFrom", CFX_1155SafeTransferFrom)
	app.Post("/CFX_1155TransferFrom", CFX_1155TransferFrom)

	app.Post("/CFX_1155FreeMintNFT", CFX_1155FreeMintNFT)
	app.Post("/CFX_1155SetEventDetail", CFX_1155SetEventDetail)
	//通用cfx 代付白名单
	app.Post("/CFX_1155SetSponrs", CFX_1155SetSponrs)
	// app.Post("/web3_sha3", CFX_OwnerOf)
	//域名服务
	app.Post("/CFX_DomainDNS", CFX_DomainDNS)
	app.Post("/CFX_UserNFTsDNS", CFX_UserNFTsDNS)
	app.Post("/CFX_DomainTimes", CFX_DomainTimes)
	app.Post("/CFX_AddDomainTime", CFX_AddDomainTime)
	app.Post("/CFX_RushToRegisterDomain", CFX_RushToRegisterDomain)
	//自动部署合约的配置
	// app.Post("/CFX_NewContractSettingData", CFX_NewContractSettingData)
	app.Run(iris.TLS(ServerIP+":"+ServerPort, "confluxserver.cer", "confluxserver.key"), iris.WithoutServerError(iris.ErrServerClosed))

}

func initClient() {
	HalfPrvDataPostclient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: (&net.Dialer{
				Timeout:   60 * time.Second,
				KeepAlive: 60 * time.Second,
			}).DialContext,
			MaxIdleConns:          4096,
			IdleConnTimeout:       600 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}
func InitServerSetting() {
	//读取配置文件
	//获得本地设置JSON
	fjson, err := os.Open("setting.json")
	if err != nil {
		fmt.Println(err, "setting.json读取错误")
	}
	var json_buff []byte = make([]byte, 1000)
	defer fjson.Close()
	cont, _ := fjson.Read(json_buff)
	json_buff = json_buff[:cont]
	fjson.Close()
	var SET setting
	err = json.Unmarshal(json_buff, &SET)
	if err != nil {
		fmt.Println(err, "setting.json 反序列化错误")
	}
	//设置本地JSON参数
	ServerIP = SET.ServerIP
	ServerPort = SET.ServerPort
	CFXNodeURL = SET.CFXNodeURL
	CFXNetID = SET.CFXNetid
	ETHNodeURL = SET.ETHNodeURL
	ETHNetID = SET.ETHNetid
	BSCNodeURL = SET.BSCNodeURL
	BSCNetID = SET.BSCNetid
	ARBNodeURL = SET.ARBNodeURL
	ARBNetID = SET.ARBNetid
	CSUATNodeURL = SET.CSUATNodeURL
	CSUATNetID = SET.CSUATNetid
	IPandPort = SET.IPandPort
	RASModel = SET.RSA
	fmt.Println("load setting success!")
	fmt.Println("ServerIP:", ServerIP)
	fmt.Println("ServerPort:", ServerPort)
	fmt.Println("CFXNetID:", CFXNetID)
	fmt.Println("CFXNodeURL:", CFXNodeURL)
	fmt.Println("ETHNetID:", ETHNetID)
	fmt.Println("ETHNodeURL:", ETHNodeURL)
	fmt.Println("BSCNetID:", BSCNetID)
	fmt.Println("BSCNodeURL:", BSCNodeURL)
	fmt.Println("ARBNetID:", ARBNetID)
	fmt.Println("ARBNodeURL:", ARBNodeURL)
	fmt.Println("CSUATNetID:", CSUATNetID)
	fmt.Println("CSUATNodeURL:", CSUATNodeURL)
	fmt.Println("IPandPort:", IPandPort)
	fmt.Println("RASModel:", RASModel)
	//区块链合约初始化
	cfxclientRPC, err = sdk.NewClient(CFXNodeURL)
	if err != nil {
		fmt.Println("failed to dial conflux node rpc", err)
		panic(err)
	}
	cfxclient2RPC, err = sdk.NewClient(CFXNodeURL, sdk.ClientOption{
		KeystorePath: "keystore",
	})
	if err != nil {
		fmt.Println("failed to dial conflux node2 rpc", err)
		panic(err)
	}
	//ETH RPC
	ethclientRPC, err = ethclient.Dial(ETHNodeURL) //https://rinkeby.infura.io"   BSCtest:https://data-seed-prebsc-1-s1.binance.org:8545        11415650
	if err != nil {
		fmt.Println("failed to dial eth node rpc", err)
		panic(err)
	}
	//BSC RPC
	bscclientRPC, err = ethclient.Dial(BSCNodeURL)
	if err != nil {
		fmt.Println("failed to dial bsc node rpc", err)
		panic(err)
	}
	//ARB RPC
	arbclientRPC, err = ethclient.Dial(ARBNodeURL)
	if err != nil {
		fmt.Println("failed to dial arb node rpc", err)
		panic(err)
	}
	//CSUAT RPC
	csuatclientRPC, err = ethclient.Dial(CSUATNodeURL)
	if err != nil {
		fmt.Println("failed to dial 招商银行 node rpc", err)
		panic(err)
	}
}
func PicePUKInit() {
	key := []byte("mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm")
	file, err := os.Open("catchp.dll") //分片服务器公钥
	if err != nil {
		return
	}
	stat, _ := file.Stat()
	data := make([]byte, stat.Size())
	file.Read(data)
	file.Close()
	pukdata := acc.AEC_CRT_Crypt(data, key)
	//转化
	block, _ := pem.Decode(pukdata)
	//3. 使用x509将编码之后的公钥解析出来
	pubInterface, err2 := x509.ParsePKIXPublicKey(block.Bytes)
	if err2 != nil {
		fmt.Println(err.Error())
	}
	PUK = pubInterface.(*rsa.PublicKey)
	key = nil
}
func ReturnPukInit() {
	file, err := os.Open("Retrunpublic.pem") //分片服务器公钥
	if err != nil {
		return
	}
	stat, _ := file.Stat()
	data := make([]byte, stat.Size())
	file.Read(data)
	file.Close()
	//转化
	block, _ := pem.Decode(data)
	//3. 使用x509将编码之后的公钥解析出来
	pubInterface, err2 := x509.ParsePKIXPublicKey(block.Bytes)
	if err2 != nil {
		fmt.Println(err.Error())
	}
	PUKReturn = pubInterface.(*rsa.PublicKey)

}
func ProjectKeysInitPrew() {
	ProjectNamedict = make(map[string]string)                    //让dict可编辑
	ProjectPublickeyCatchdict = make(map[string]*rsa.PrivateKey) //让dict可编辑
	APPIDdict = make(map[string]string)                          //让dict可编辑
	ContractAddressMap = make(map[string]common.Address)         //让dict可编辑ProjectAPPIDMap
}
func ProjectKeysInit() {
	go func() {
		files, number, list_filename := acc.GetFilelist("./projects")
		for i := 0; i < number; i++ {
			if strings.Contains(list_filename[i], "APPID") {
				ProjectAPPID, err := acc.Lode1(files[i])
				if err != nil {
					panic(err)
				}
				//keys里面存项目公钥私钥
				ProjectName := strings.ReplaceAll(list_filename[i], "APPID", "")
				// fmt.Println(string(proAPPID))
				APPIDdict[ProjectName] = string(ProjectAPPID) //优化加载
				ProjectNamedict[acc.CalculateHashcode(string(ProjectAPPID))] = ProjectName
				if RASModel == "single" {
					fmt.Println("sigle")
					file, err := os.Open("globleprivate.pem")
					if err != nil {
						panic(err)
					}
					stat, _ := file.Stat() //得到文件属性信息
					ProjectPrvkey := make([]byte, stat.Size())
					file.Read(ProjectPrvkey)
					file.Close()
					if err != nil {
						fmt.Println("找不到", "globlepublic", "APPID")
						panic(err)
					}
					// fmt.Println(string(ProjectPrvkey))
					//1. 打开并读取私钥文件
					//2. 将得到的字符串进行pem解码
					block, _ := pem.Decode(ProjectPrvkey)
					// fmt.Println(block)
					//3. 使用x509将编码之后的私钥解析出来
					privateKey, err3 := x509.ParsePKCS1PrivateKey(block.Bytes)
					if err3 != nil {
						panic(err3)
					}
					ProjectPublickeyCatchdict[ProjectName] = privateKey
				} else {
					ProjectPrvkey, err := acc.Lode1("./keys/" + ProjectName + "prk")
					if err != nil {
						fmt.Println("找不到", ProjectName, "APPID")
						panic(err)
					}
					//1. 打开并读取私钥文件
					//2. 将得到的字符串进行pem解码
					block, _ := pem.Decode(ProjectPrvkey)
					// fmt.Println(block)
					//3. 使用x509将编码之后的私钥解析出来
					privateKey, err3 := x509.ParsePKCS1PrivateKey(block.Bytes)
					if err3 != nil {
						panic(err3)
					}
					ProjectPublickeyCatchdict[ProjectName] = privateKey
				}

				//projects里面存项目合约地址和APPID
				contractAddr, err := acc.Lode1("./projects/" + ProjectName + "CONTRACT")
				if err != nil {
					fmt.Println("找不到", ProjectName, "CONTRACT")
					panic(err)
				}
				ContractAddressMap[ProjectName] = common.HexToAddress(string(contractAddr))

				fmt.Println("加载项目：", ProjectName)

			}
		}
		time.Sleep(10 * time.Minute)
	}()

}
func SQLInit() {
	//SQL
	conn := "user:password@tcp(127.0.0.1:3306)/tikverse?charset=utf8"
	dbg, err := sql.Open("mysql", conn)
	if err != nil {
		fmt.Println(err, "数据库链接错误")
		return
	} else {
		fmt.Println("数据库链接成功!")
	}
	GlobalDB = dbg
}
func StmInit() {
	myUserRegitStm, err := GlobalDB.Prepare("replace into account_data(account_data.address,account_data.ethaddress,account_data.data,account_data.key) VALUES(?,?,?,?)")
	if err != nil {
		panic(err)
	}
	UserRegitStm = myUserRegitStm
	//查询数据库
	SELECTAddressStm, err = GlobalDB.Prepare("SELECT account_data.data,account_data.key FROM tikverse.account_data WHERE account_data.address=?")
	if err != nil {
		panic(err)
	}
	SELECTETHAddressStm, err = GlobalDB.Prepare("SELECT account_data.data,account_data.key FROM tikverse.account_data WHERE account_data.ethaddress=?")
	if err != nil {
		panic(err)
	}
	ALL_SELECTAddressStm, err = GlobalDB.Prepare("SELECT account_data.data,account_data.key,account_data.address,account_data.ethaddress FROM tikverse.account_data ")
	if err != nil {
		panic(err)
	}
}
func text(ctx iris.Context) {
	ctx.WriteString("test 测试！")
	return
}
func Regit(password string) (string, string) {
	t1 := time.Now().UnixMilli()
	prv, addr, ethaddr := acc.CreatePrivateKey()
	prv2, _, _ := acc.CreatePrivateKey()
	// fmt.Println("prv:", prv)
	// fmt.Println("addr:", addr)
	// fmt.Println("cfxaddr:", cfxaddress.MustNewFromHex(addr, 1).String())//这个地址和ID绑定用处不大
	//生成一个ECC
	ECCprv := acc.CreateECCPrivateKey()
	priKey, err := crypto.HexToECDSA(ECCprv)
	if err != nil {
		return err.Error(), err.Error()
	}
	prk2 := ecies.ImportECDSA(priKey)
	puk2 := prk2.PublicKey
	//ECCprv 加密 prv
	encode, err := acc.ECCEncrypt([]byte(prv), puk2)
	// fmt.Println("encode", hex.EncodeToString(encode))
	encode2, err := acc.ECCEncrypt([]byte(prv2), puk2)
	if err != nil {
		return err.Error(), err.Error()
	}
	// fmt.Println("加密后prv为：", hex.EncodeToString(encode), len(encode))
	// fmt.Println("加密后100prv为：", hex.EncodeToString(encode[:113]), len(encode[:113])) //100
	// fmt.Println("加密后77prv为：", hex.EncodeToString(encode[113:]), len(encode[113:]))  //77
	// fmt.Println("加密后prv为：", hex.EncodeToString(encode2), len(encode2))
	//encode[113:]
	//拆分
	pr1 := encode[:113]
	pr2 := encode[113:]
	// fmt.Println("拆分的部分64byte：", hex.EncodeToString(pr2), len(pr2))
	cfx := cfxaddress.MustNewFromHex(string(addr))

	// fmt.Println("DeAddress", string(DeAddress))
	fmt.Println("Regit ethaddr", ethaddr)
	// 发送到另一个服务
	body := HalfPrvDataPost(IPandPort, "SetHalfPrvData", APPID_PrvKeyPiceServer, cfx.MustGetCommonAddress().String(), ethaddr, hex.EncodeToString(pr2), "shpd")
	fmt.Println(string(body))
	if !strings.Contains(string(body), "SHPDS") {
		fmt.Println("HalfPrvDataPost 失败！")
		return "HalfPrvDataPost 失败！", "HalfPrvDataPost 失败！"
	}
	// fpr1 := encode2[:113]
	fpr2 := encode2[113:]
	fpr := acc.BytesCombine1(pr1, fpr2)
	// fmt.Println("混淆合并后：", hex.EncodeToString(fpr), len(fpr))
	//使用AES加密ECCprv
	message := []byte(ECCprv)
	//指定密钥
	bu := []byte(acc.CalculateHashcode(password))
	bu = bu[:32]
	key := bu
	//加密
	cipherText := acc.AEC_CRT_Crypt(message, key) //
	// fmt.Println("加密后ECCprv为：", hex.EncodeToString(cipherText), len(cipherText))
	// //解密
	// plainText := AEC_CRT_Crypt(cipherText, key)
	// fmt.Println("解密后为：", string(plainText))
	//存入 数据库：ID 电话 Address  ECCPrv  prv
	//分割 prv 长度177
	//写入数据库
	var KD KeyData_Message
	KD.data = hex.EncodeToString(fpr)
	KD.key = hex.EncodeToString(cipherText)
	_, err = UserRegitStm.Exec(cfx.MustGetCommonAddress().String(), ethaddr, KD.data, KD.key)
	if err != nil {
		return err.Error(), err.Error()
	}
	GetCFXDataCatch.Set(cfx.MustGetCommonAddress().String(), KD, cache.NoExpiration)
	GetETHDataCatch.Set(ethaddr, KD, cache.NoExpiration)
	// wg.Done()
	t2 := time.Now().UnixMilli()
	fmt.Println("UserRegit耗时：", t2-t1)
	cfxaddress := cfxaddress.MustNewFromHex(addr, CFXNetID)

	return cfxaddress.MustGetBase32Address(), ethaddr
}
func RegitByPRK(password string, Prk string) (string, string) {
	t1 := time.Now().UnixMilli()
	prv, addr, ethaddr := acc.CreatePrivateKeyByPRK(Prk)
	if prv == "" {
		fmt.Println("私钥错误")
		return "", ""
	}
	prv2, _, _ := acc.CreatePrivateKey()
	// fmt.Println("prv:", prv)
	// fmt.Println("addr:", addr)
	// fmt.Println("cfxaddr:", cfxaddress.MustNewFromHex(addr, 1).String())//这个地址和ID绑定用处不大
	//生成一个ECC
	ECCprv := acc.CreateECCPrivateKey()
	priKey, err := crypto.HexToECDSA(ECCprv)
	if err != nil {
		return err.Error(), err.Error()
	}
	prk2 := ecies.ImportECDSA(priKey)
	puk2 := prk2.PublicKey
	//ECCprv 加密 prv
	encode, err := acc.ECCEncrypt([]byte(prv), puk2)
	// fmt.Println("encode", hex.EncodeToString(encode))
	encode2, err := acc.ECCEncrypt([]byte(prv2), puk2)
	if err != nil {
		return err.Error(), err.Error()
	}
	// fmt.Println("加密后prv为：", hex.EncodeToString(encode), len(encode))
	// fmt.Println("加密后100prv为：", hex.EncodeToString(encode[:113]), len(encode[:113])) //100
	// fmt.Println("加密后77prv为：", hex.EncodeToString(encode[113:]), len(encode[113:]))  //77
	// fmt.Println("加密后prv为：", hex.EncodeToString(encode2), len(encode2))
	//encode[113:]
	//拆分
	pr1 := encode[:113]
	pr2 := encode[113:]
	// fmt.Println("拆分的部分64byte：", hex.EncodeToString(pr2), len(pr2))
	cfx := cfxaddress.MustNewFromHex(string(addr))

	// fmt.Println("DeAddress", string(DeAddress))
	fmt.Println("RegitByPRK ethaddr", ethaddr)
	// 发送到另一个服务
	body := HalfPrvDataPost(IPandPort, "SetHalfPrvData", APPID_PrvKeyPiceServer, cfx.MustGetCommonAddress().String(), ethaddr, hex.EncodeToString(pr2), "shpd")
	fmt.Println(string(body))
	if !strings.Contains(string(body), "SHPDS") {
		fmt.Println("HalfPrvDataPost 失败！")
		return "HalfPrvDataPost 失败！", "HalfPrvDataPost 失败！"
	}
	// fpr1 := encode2[:113]
	fpr2 := encode2[113:]
	fpr := acc.BytesCombine1(pr1, fpr2)
	// fmt.Println("混淆合并后：", hex.EncodeToString(fpr), len(fpr))
	//使用AES加密ECCprv
	message := []byte(ECCprv)
	//指定密钥
	bu := []byte(acc.CalculateHashcode(password))
	bu = bu[:32]
	key := bu
	//加密
	cipherText := acc.AEC_CRT_Crypt(message, key) //
	// fmt.Println("加密后ECCprv为：", hex.EncodeToString(cipherText), len(cipherText))
	// //解密
	// plainText := AEC_CRT_Crypt(cipherText, key)
	// fmt.Println("解密后为：", string(plainText))
	//存入 数据库：ID 电话 Address  ECCPrv  prv
	//分割 prv 长度177
	//写入数据库
	var KD KeyData_Message
	KD.data = hex.EncodeToString(fpr)
	KD.key = hex.EncodeToString(cipherText)
	_, err = UserRegitStm.Exec(cfx.MustGetCommonAddress().String(), ethaddr, ethaddr, KD.data, KD.key)
	if err != nil {
		return err.Error(), err.Error()
	}
	GetCFXDataCatch.Set(cfx.MustGetCommonAddress().String(), KD, cache.NoExpiration)
	GetETHDataCatch.Set(ethaddr, KD, cache.NoExpiration)
	// wg.Done()
	t2 := time.Now().UnixMilli()
	fmt.Println("UserRegit耗时：", t2-t1)
	cfxaddress := cfxaddress.MustNewFromHex(addr, CFXNetID)
	return cfxaddress.MustGetBase32Address(), ethaddr
}

// //////////////////////////////////耐克模式////////////////////////////////////////
func CFX_AdminCreateNFTBatch_URI(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.AdminCreateNFTBatch_URI_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeNonce, err := acc.PrivateDecode(Msg.Nonce, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeLifeTime, err := acc.PrivateDecode(Msg.LifeTime, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DePassword, err := acc.PrivateDecode(Msg.Password, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeFrom, err := acc.PrivateDecode(Msg.From, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		int64DeNonce := int64(binary.BigEndian.Uint64(DeNonce))
		int64DeLifeTime := int64(binary.BigEndian.Uint64(DeLifeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			//tos
			var DeTos []common.Address
			for i := 0; i < len(Msg.Tos); i++ {
				cfx := cfxaddress.MustNewFromBase32(Msg.Tos[i])
				DeTos = append(DeTos, cfx.MustGetCommonAddress())
			}
			cfx2 := cfxaddress.MustNewFromBase32(string(DeFrom))
			key, str := Getdata_Catch(cfx2.MustGetCommonAddress().String(), string(DePassword), "cfx")
			if str != "" {
				ctx.Write([]byte(fmt.Sprint(str)))
				return
			}
			// fmt.Println(len(DeTos))
			hash, ids, err := acc.CFX_bc_AdminCreateNFTBatch_URI(int64DeNonce, int64DeLifeTime, string(DeFrom), string(key), DeTos, Msg.URIS, ContractAddressMap[projectName], cfxclient2RPC)
			key = nil
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			var RES acc.AdmincreateNFTBatchRes
			RES.Hash = hash
			for k := 0; k < len(ids); k++ {
				var NFT acc.NFTS
				NFT.Id = ids[k]
				NFT.Owner = Msg.Tos[k]
				RES.Nfts = append(RES.Nfts, NFT)
			}
			buffer, err := json.Marshal(RES)
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			ctx.Write(buffer)
			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
}

/////////////////////////////CONFLUX CHAIN//////////////////////////////////

func UserRegitByPrivateKey(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.UserRegitByPrivateKey_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DePassword, err := acc.PrivateDecode(Msg.Data, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		PRK, err := acc.PrivateDecode(Msg.PRK, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			cfxaddress, ethaddress := RegitByPRK(string(DePassword), string(PRK))
			RESS := &acc.UserRegitRes_Message{}
			RESS.Confluxaddress = cfxaddress
			RESS.ETHaddress = ethaddress
			bF, err := json.Marshal(RESS)
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			ctx.Write(bF)
			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
}
func UserRegit(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.UserRegit_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeData, err := acc.PrivateDecode(Msg.Data, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			cfxaddress, ethaddress := Regit(string(DeData))
			RESS := &acc.UserRegitRes_Message{}
			RESS.Confluxaddress = cfxaddress
			RESS.ETHaddress = ethaddress
			bF, err := json.Marshal(RESS)
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			ctx.Write(bF)

			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
}
func CFX_TotalSupply(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.UserRegit_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		// DeData, err := acc.PrivateDecode(Msg.Data, prvCa)
		// if err != nil {
		// 	ctx.Write([]byte(fmt.Sprint(err)))
		// 	return
		// }
		prvCa = nil
		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			// fmt.Println(ContractAddressMap[projectName])
			total, err := acc.CFX_bc_NFT_INDEX(ContractAddressMap[projectName], cfxclientRPC)
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			ctx.Write([]byte(total.String()))
			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
}
func CFX_AdminCreateNFT(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.AdminCreateNFT_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeNonce, err := acc.PrivateDecode(Msg.Nonce, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeLifeTime, err := acc.PrivateDecode(Msg.LifeTime, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DePassword, err := acc.PrivateDecode(Msg.Password, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeFrom, err := acc.PrivateDecode(Msg.From, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeTo, err := acc.PrivateDecode(Msg.To, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		int64DeNonce := int64(binary.BigEndian.Uint64(DeNonce))
		int64DeLifeTime := int64(binary.BigEndian.Uint64(DeLifeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			cfx := cfxaddress.MustNewFromBase32(string(DeFrom))
			// app.Logger().Info(cfx.MustGetCommonAddress().String())
			// app.Logger().Info(string(DePassword))

			key, str := Getdata_Catch(cfx.MustGetCommonAddress().String(), string(DePassword), "cfx")
			// key, str := Getdata_Catch(cfx.MustGetCommonAddress().String(), string(DePassword))
			if str != "" {
				ctx.Write([]byte(fmt.Sprint(str)))
				return
			}
			// fmt.Println(1)DePassword
			// fmt.Println("int64DeNonce", int64DeNonce)
			hash, err := acc.CFX_bc_AdminCreateNFT(int64DeNonce, int64DeLifeTime, string(DeFrom), string(key), string(DeTo), ContractAddressMap[projectName], cfxclient2RPC)
			key = nil
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			ctx.Write([]byte(hash))

			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
}
func CFX_AdminCreateNFTBatch(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.AdminCreateNFTBatch_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeNonce, err := acc.PrivateDecode(Msg.Nonce, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeLifeTime, err := acc.PrivateDecode(Msg.LifeTime, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DePassword, err := acc.PrivateDecode(Msg.Password, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeFrom, err := acc.PrivateDecode(Msg.From, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		int64DeNonce := int64(binary.BigEndian.Uint64(DeNonce))
		int64DeLifeTime := int64(binary.BigEndian.Uint64(DeLifeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			//tos
			var DeTos []common.Address
			for i := 0; i < len(Msg.Tos); i++ {
				cfx := cfxaddress.MustNewFromBase32(Msg.Tos[i])
				DeTos = append(DeTos, cfx.MustGetCommonAddress())
			}
			cfx2 := cfxaddress.MustNewFromBase32(string(DeFrom))
			key, str := Getdata_Catch(cfx2.MustGetCommonAddress().String(), string(DePassword), "cfx")
			if str != "" {
				ctx.Write([]byte(fmt.Sprint(str)))
				return
			}
			// fmt.Println(len(DeTos))
			hash, ids, err := acc.CFX_bc_AdminCreateNFTBatch(int64DeNonce, int64DeLifeTime, string(DeFrom), string(key), DeTos, ContractAddressMap[projectName], cfxclient2RPC)
			key = nil
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			var RES acc.AdmincreateNFTBatchRes
			RES.Hash = hash
			for k := 0; k < len(ids); k++ {
				var NFT acc.NFTS
				NFT.Id = ids[k]
				NFT.Owner = Msg.Tos[k]
				RES.Nfts = append(RES.Nfts, NFT)
			}
			buffer, err := json.Marshal(RES)
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			ctx.Write(buffer)
			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
}
func CFX_AdminTransferNFTBatch(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.AdminTransferNFTBatch_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeNonce, err := acc.PrivateDecode(Msg.Nonce, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeLifeTime, err := acc.PrivateDecode(Msg.LifeTime, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DePassword, err := acc.PrivateDecode(Msg.Password, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeFrom, err := acc.PrivateDecode(Msg.From, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		int64DeNonce := int64(binary.BigEndian.Uint64(DeNonce))
		int64DeLifeTime := int64(binary.BigEndian.Uint64(DeLifeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			//tos
			var DeTos []common.Address
			for i := 0; i < len(Msg.Tos); i++ {
				cfx := cfxaddress.MustNewFromBase32(Msg.Tos[i])
				DeTos = append(DeTos, cfx.MustGetCommonAddress())
			}
			//ids
			var ids []*big.Int

			for i := 0; i < len(Msg.Ids); i++ {
				// fmt.Println("Msg.Ids:", Msg.Ids[i])
				var bg *big.Int = big.NewInt(1)
				bi, bo := (bg).SetString(Msg.Ids[i], 10)
				if !bo {
					ctx.Write([]byte("Msg.Ids[i] to *big.int Error"))
					return
				}
				ids = append(ids, bi)
			}
			cfx2 := cfxaddress.MustNewFromBase32(string(DeFrom))
			key, str := Getdata_Catch(cfx2.MustGetCommonAddress().String(), string(DePassword), "cfx")
			if str != "" {
				ctx.Write([]byte(fmt.Sprint(str)))
				return
			}
			hash, err := acc.CFX_bc_AdminTransferNFTBatch(int64DeNonce, int64DeLifeTime, string(DeFrom), string(key), DeTos, ids, ContractAddressMap[projectName], cfxclient2RPC)
			key = nil
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			ctx.Write([]byte(hash))

			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
}
func CFX_TransferFrom(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.TransferFrom_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeNonce, err := acc.PrivateDecode(Msg.Nonce, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeLifeTime, err := acc.PrivateDecode(Msg.LifeTime, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DePassword, err := acc.PrivateDecode(Msg.Password, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeFrom, err := acc.PrivateDecode(Msg.From, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		int64DeNonce := int64(binary.BigEndian.Uint64(DeNonce))
		int64DeLifeTime := int64(binary.BigEndian.Uint64(DeLifeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			cfx2 := cfxaddress.MustNewFromBase32(string(DeFrom))
			key, str := Getdata_Catch(cfx2.MustGetCommonAddress().String(), string(DePassword), "cfx")
			if str != "" {
				ctx.Write([]byte(fmt.Sprint(str)))
				return
			}
			ID, bo := big.NewInt(1).SetString(Msg.Id, 10)
			if !bo {
				ctx.Write([]byte("Id to *big.int Error"))
				return
			}
			cfxto := cfxaddress.MustNewFromBase32(Msg.To)
			hash, err := acc.CFX_bc_TransferFrom(int64DeNonce, int64DeLifeTime, string(DeFrom), string(key), cfxto.MustGetCommonAddress(), ID, ContractAddressMap[projectName], cfxclient2RPC)
			key = nil
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			ctx.Write([]byte(hash))

			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
}
func CFX_UserNFTs(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.UserNFTs_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeFrom, err := acc.PrivateDecode(Msg.From, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			// fmt.Println(1)DePassword
			nfts, err := acc.CFX_bc_UserNFTs(string(DeFrom), ContractAddressMap[projectName], cfxclient2RPC)
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			if len(nfts) > 0 {
				var nftsj []string
				for i := 0; i < len(nfts); i++ {
					nftsj = append(nftsj, nfts[i].String())
				}
				ctx.WriteString(strings.Join(nftsj, ","))
			} else {
				ctx.Write([]byte(""))
			}

			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
}
func CFX_TokenUri(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.UserNFTUri_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeID, err := acc.PrivateDecode(Msg.ID, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			// fmt.Println(1)DePassword
			var BI big.Int
			BG, boo := BI.SetString(string(DeID), 10)
			if !boo {
				ctx.Write([]byte("err big.Int SetString"))
				return
			}
			Uri, err := acc.CFX_bc_TokenUri(BG, ContractAddressMap[projectName], cfxclient2RPC)
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			ctx.WriteString(Uri)
			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
}
func CFX_OwnerOf(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.UserNFTUri_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeID, err := acc.PrivateDecode(Msg.ID, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			// fmt.Println(1)DePassword
			BI := big.NewInt(0)
			BG, boo := BI.SetString(string(DeID), 10)
			if !boo {
				ctx.Write([]byte("err big.Int SetString"))
				return
			}
			owneraddress, err := acc.CFX_bc_ownerOf(BG, ContractAddressMap[projectName], cfxclient2RPC)
			if err != nil {
				ctx.Write([]byte(err.Error()))
				return
			}
			ctx.WriteString(cfxaddress.MustNewFromCommon(owneraddress, CFXNetID).String())
			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
}
func CFX_ApproveForAll(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.ApproveAll_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeNonce, err := acc.PrivateDecode(Msg.Nonce, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeLifeTime, err := acc.PrivateDecode(Msg.LifeTime, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DePassword, err := acc.PrivateDecode(Msg.Password, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeFrom, err := acc.PrivateDecode(Msg.From, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		int64DeNonce := int64(binary.BigEndian.Uint64(DeNonce))
		int64DeLifeTime := int64(binary.BigEndian.Uint64(DeLifeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			cfx2 := cfxaddress.MustNewFromBase32(string(DeFrom))
			key, str := Getdata_Catch(cfx2.MustGetCommonAddress().String(), string(DePassword), "cfx")
			if str != "" {
				ctx.Write([]byte(fmt.Sprint(str)))
				return
			}
			IsApprove := false
			if Msg.IsApprove == "true" {
				IsApprove = true
			}
			cfxto := cfxaddress.MustNewFromBase32(Msg.To)
			hash, err := acc.CFX_bc_setApprovalForAll(int64DeNonce, int64DeLifeTime, string(DeFrom), cfxto.MustGetCommonAddress(), string(key), IsApprove, ContractAddressMap[projectName], cfxclient2RPC)
			key = nil
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			ctx.Write([]byte(hash))

			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
}
func CFX_IsApproveForAll(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.IsApproveAll_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		DeFrom, err := acc.PrivateDecode(Msg.From, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			cfxto := cfxaddress.MustNewFromBase32(Msg.To)
			boo, err := acc.CFX_bc_IsApprovalForAll(string(DeFrom), cfxto.MustGetCommonAddress(), ContractAddressMap[projectName], cfxclientRPC)
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			ctx.WriteString(fmt.Sprint(boo))
			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
}
func CFX_AdminCreateDomainBatch(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.AdminCreateDmainBatch_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeNonce, err := acc.PrivateDecode(Msg.Nonce, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeLifeTime, err := acc.PrivateDecode(Msg.LifeTime, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DePassword, err := acc.PrivateDecode(Msg.Password, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeFrom, err := acc.PrivateDecode(Msg.From, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		int64DeNonce := int64(binary.BigEndian.Uint64(DeNonce))
		int64DeLifeTime := int64(binary.BigEndian.Uint64(DeLifeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			//tos
			var DeTos []common.Address
			for i := 0; i < len(Msg.Tos); i++ {
				cfx := cfxaddress.MustNewFromBase32(Msg.Tos[i])
				DeTos = append(DeTos, cfx.MustGetCommonAddress())
			}
			cfx2 := cfxaddress.MustNewFromBase32(string(DeFrom))
			key, str := Getdata_Catch(cfx2.MustGetCommonAddress().String(), string(DePassword), "cfx")
			if str != "" {
				ctx.Write([]byte(fmt.Sprint(str)))
				return
			}
			// fmt.Println(len(DeTos))
			hash, _, err := acc.CFX_Domain_AdminCreateNFTBatch(int64DeNonce, int64DeLifeTime, string(DeFrom), string(key), DeTos, Msg.Uris, ContractAddressMap[projectName], cfxclient2RPC)
			key = nil
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			ctx.Write([]byte(hash))
			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
	}
}
func CFX_Burn(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.TransferFrom_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeNonce, err := acc.PrivateDecode(Msg.Nonce, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeLifeTime, err := acc.PrivateDecode(Msg.LifeTime, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DePassword, err := acc.PrivateDecode(Msg.Password, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeFrom, err := acc.PrivateDecode(Msg.From, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		DeChainType, err := acc.PrivateDecode(Msg.ChainType, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		int64DeNonce := int64(binary.BigEndian.Uint64(DeNonce))
		int64DeLifeTime := int64(binary.BigEndian.Uint64(DeLifeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			if string(DeChainType) != "cfx" {
				ctx.Write([]byte(string(DeChainType) + " not support"))
				return
			}
			cfx2 := cfxaddress.MustNewFromBase32(string(DeFrom))
			key, str := Getdata_Catch(cfx2.MustGetCommonAddress().String(), string(DePassword), "cfx")
			if str != "" {
				ctx.Write([]byte(fmt.Sprint(str)))
				return
			}
			ID, bo := big.NewInt(1).SetString(Msg.Id, 10)
			if !bo {
				ctx.Write([]byte("Id to *big.int Error"))
				return
			}
			hash, err := acc.CFX_bc_burn(int64DeNonce, int64DeLifeTime, string(DeFrom), ID, string(key), ContractAddressMap[projectName], cfxclient2RPC)
			key = nil
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			ctx.Write([]byte(hash))

			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
}

// ////////////////////////////CRC1155///////////////////////////////////////
func CFX_1155TotalSupply(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.UserRegit_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		// DeData, err := acc.PrivateDecode(Msg.Data, prvCa)
		// if err != nil {
		// 	ctx.Write([]byte(fmt.Sprint(err)))
		// 	return
		// }
		prvCa = nil
		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			// fmt.Println(ContractAddressMap[projectName])
			total, err := acc.CFX_bc_totalNFT(ContractAddressMap[projectName], cfxclientRPC)
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			ctx.Write([]byte(total.String()))

			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
}
func CFX_1155TotalAmount(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.UserNFTUri_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeID, err := acc.PrivateDecode(Msg.ID, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			// fmt.Println(1)DePassword
			BI := big.NewInt(0)
			BG, boo := BI.SetString(string(DeID), 10)
			if !boo {
				ctx.Write([]byte("err big.Int SetString"))
				return
			}
			amount, err := acc.CFX_bc_totalNFTAmount(ContractAddressMap[projectName], BG, cfxclient2RPC)
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			ctx.WriteString(amount.String())
			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
}
func CFX_1155BalanceOf(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.UserNFT1155balance_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeID, err := acc.PrivateDecode(Msg.ID, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeAccount, err := acc.PrivateDecode(Msg.Account, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			// fmt.Println(1)DePassword
			BI := big.NewInt(1)
			BG, boo := BI.SetString(string(DeID), 10)
			if !boo {
				ctx.Write([]byte("err big.Int SetString"))
				return
			}
			ACCOUNT := cfxaddress.MustNewFromBase32(string(DeAccount))
			// fmt.Println(BG.String())
			amount, err := acc.CFX_bc_balnaceOf(ACCOUNT.MustGetCommonAddress(), BG, ContractAddressMap[projectName], cfxclient2RPC)
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			ctx.WriteString(amount.String())
			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
	}
}
func CFX_1155BalanceOfBatch(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.UserNFT1155balanceBatch_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			// fmt.Println(1)DePassword
			var TOS []common.Address
			for i := 0; i < len(Msg.Accounts); i++ {
				addr := cfxaddress.MustNewFromBase32(Msg.Accounts[i])
				TOS = append(TOS, addr.MustGetCommonAddress())
			}
			var IDS []*big.Int
			for i := 0; i < len(Msg.IDs); i++ {
				BI := big.NewInt(0)
				BNi, boo := BI.SetString(Msg.IDs[i], 10)
				if !boo {
					ctx.Write([]byte("err big.Int SetString"))
					return
				}
				IDS = append(IDS, BNi)
			}
			// fmt.Println(BG.String())
			amount, err := acc.CFX_bc_balnaceOfBatch(TOS, IDS, ContractAddressMap[projectName], cfxclient2RPC)
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			// BUF, err := json.Marshal(amount)
			// if err != nil {
			// 	ctx.WriteString(err.Error())
			// 	return
			// }
			var DSS string = ""
			for i := 0; i < len(amount); i++ {
				DSS += amount[i].String() + ","
			}
			DSS = DSS[:len(DSS)-1]
			ctx.WriteString(DSS)
			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
	}
}
func CFX_1155AdminCreateNFT(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.UserNFT1155AdminCreateNFT_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeNonce, err := acc.PrivateDecode(Msg.Nonce, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeLifeTime, err := acc.PrivateDecode(Msg.LifeTime, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DePassword, err := acc.PrivateDecode(Msg.Password, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeFrom, err := acc.PrivateDecode(Msg.From, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeTo, err := acc.PrivateDecode(Msg.To, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeNumber, err := acc.PrivateDecode(Msg.Number, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeCreator, err := acc.PrivateDecode(Msg.Creator, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		int64DeNonce := int64(binary.BigEndian.Uint64(DeNonce))
		int64DeLifeTime := int64(binary.BigEndian.Uint64(DeLifeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			cfx := cfxaddress.MustNewFromBase32(string(DeFrom))
			BI := big.NewInt(0)
			BNumber, boo := BI.SetString(string(DeNumber), 10)
			if !boo {
				ctx.Write([]byte("err big.Int SetString"))
				return
			}

			key, str := Getdata_Catch(cfx.MustGetCommonAddress().String(), string(DePassword), "cfx")
			// key, str := Getdata_Catch(cfx.MustGetCommonAddress().String(), string(DePassword))
			if str != "" {
				ctx.Write([]byte(fmt.Sprint(str)))
				return
			}
			// fmt.Println("Deto", string(DeTo), string(DeCreator), Msg.Nfturi, string(Msg.To))
			_, nftid, err := acc.CFX_bc_AdminCreateEventNFT(int64DeNonce, int64DeLifeTime, BNumber, string(DeFrom), string(key), string(DeTo), ContractAddressMap[projectName], common.HexToAddress(string(DeCreator)), Msg.Nfturi, cfxclient2RPC)
			key = nil
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			ctx.WriteString(nftid)

			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
	}
}
func CFX_1155AdminCreateNFTBatch(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.UserNFT1155AdminCreateNFTBatch_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeNonce, err := acc.PrivateDecode(Msg.Nonce, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeLifeTime, err := acc.PrivateDecode(Msg.LifeTime, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DePassword, err := acc.PrivateDecode(Msg.Password, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		int64DeNonce := int64(binary.BigEndian.Uint64(DeNonce))
		int64DeLifeTime := int64(binary.BigEndian.Uint64(DeLifeTime))
		now := time.Now().Unix()
		if now-int64Time < 120 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			cfx := cfxaddress.MustNewFromBase32(Msg.From)
			var NUMBERS []*big.Int
			for i := 0; i < len(Msg.Numbers); i++ {
				BI := big.NewInt(0)
				BNumber, boo := BI.SetString(string(Msg.Numbers[i]), 10)
				if !boo {
					ctx.Write([]byte("err big.Int SetString"))
					return
				}
				NUMBERS = append(NUMBERS, BNumber)
			}
			var TOS []common.Address
			for i := 0; i < len(Msg.Tos); i++ {
				cfx := cfxaddress.MustNewFromBase32(Msg.Tos[i])
				TOS = append(TOS, cfx.MustGetCommonAddress())
			}
			var CREATORS []common.Address
			for i := 0; i < len(Msg.Creators); i++ {
				cfx := cfxaddress.MustNewFromBase32(Msg.Creators[i])
				CREATORS = append(CREATORS, cfx.MustGetCommonAddress())
			}
			key, str := Getdata_Catch(cfx.MustGetCommonAddress().String(), string(DePassword), "cfx")
			// key, str := Getdata_Catch(cfx.MustGetCommonAddress().String(), string(DePassword))
			if str != "" {
				ctx.Write([]byte(fmt.Sprint(str)))
				return
			}
			// fmt.Println("Deto", string(DeTo), string(DeCreator), Msg.Nfturi, string(Msg.To))
			hash, ids, err := acc.CFX_bc_AdminCreateEventNFTBatch(int64DeNonce, int64DeLifeTime, NUMBERS, Msg.From, string(key), TOS, ContractAddressMap[projectName], CREATORS, Msg.Nfturis, cfxclient2RPC)
			key = nil
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			var RES acc.AdmincreateNFTBatchRes
			RES.Hash = hash
			for k := 0; k < len(ids); k++ {
				var NFT acc.NFTS
				NFT.Id = ids[k]
				NFT.Owner = TOS[k].String()
				RES.Nfts = append(RES.Nfts, NFT)
			}
			buffer, err := json.Marshal(RES)
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			ctx.Write(buffer)
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
	}
}
func CFX_1155AdminSafeTransferNFTBatch(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.UserNFT1155AdminSafeTransferBatchNFT_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeNonce, err := acc.PrivateDecode(Msg.Nonce, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeLifeTime, err := acc.PrivateDecode(Msg.LifeTime, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DePassword, err := acc.PrivateDecode(Msg.Password, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeFrom, err := acc.PrivateDecode(Msg.From, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		int64DeNonce := int64(binary.BigEndian.Uint64(DeNonce))
		int64DeLifeTime := int64(binary.BigEndian.Uint64(DeLifeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			cfx := cfxaddress.MustNewFromBase32(string(DeFrom))
			var TOS []common.Address
			for i := 0; i < len(Msg.Tos); i++ {
				cfx := cfxaddress.MustNewFromBase32(Msg.Tos[i])
				TOS = append(TOS, cfx.MustGetCommonAddress())
			}
			var IDS []*big.Int
			for i := 0; i < len(Msg.IDs); i++ {
				BI := big.NewInt(0)
				BNi, boo := BI.SetString(Msg.IDs[i], 10)
				if !boo {
					ctx.Write([]byte("err big.Int SetString"))
					return
				}
				IDS = append(IDS, BNi)
			}
			var NUMBERS []*big.Int
			BIn := big.NewInt(0)
			for i := 0; i < len(Msg.Numbers); i++ {
				BNui, boo := BIn.SetString(Msg.Numbers[i], 10)
				if !boo {
					ctx.Write([]byte("err big.Int SetString"))
					return
				}
				NUMBERS = append(NUMBERS, BNui)
			}

			key, str := Getdata_Catch(cfx.MustGetCommonAddress().String(), string(DePassword), "cfx")
			// key, str := Getdata_Catch(cfx.MustGetCommonAddress().String(), string(DePassword))
			if str != "" {
				ctx.Write([]byte("Getdata" + fmt.Sprint(str)))
				return
			}
			hash, err := acc.CFX_bc_AdminTransferEventNFTBatch(int64DeNonce, int64DeLifeTime, string(DeFrom), string(key), TOS, IDS, NUMBERS, ContractAddressMap[projectName], cfxclient2RPC)
			key = nil
			if err != nil {
				ctx.Write([]byte("CFX_bc_AdminTransferEventNFTBatch:" + fmt.Sprint(err)))
				return
			}
			ctx.Write([]byte(hash))

			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
	}
}
func CFX_1155SafeTransferFrom(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.SafeTransferFrom1155_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeNonce, err := acc.PrivateDecode(Msg.Nonce, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeLifeTime, err := acc.PrivateDecode(Msg.LifeTime, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DePassword, err := acc.PrivateDecode(Msg.Password, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeFrom, err := acc.PrivateDecode(Msg.From, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		int64DeNonce := int64(binary.BigEndian.Uint64(DeNonce))
		int64DeLifeTime := int64(binary.BigEndian.Uint64(DeLifeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			cfx2 := cfxaddress.MustNewFromBase32(string(DeFrom))
			key, str := Getdata_Catch(cfx2.MustGetCommonAddress().String(), string(DePassword), "cfx")
			if str != "" {
				ctx.Write([]byte(fmt.Sprint(str)))
				return
			}
			ID, bo := big.NewInt(1).SetString(Msg.Id, 10)
			if !bo {
				ctx.Write([]byte("Id to *big.int Error"))
				return
			}
			AMOUNT, bo := big.NewInt(1).SetString(Msg.Amount, 10)
			if !bo {
				ctx.Write([]byte("Amount to *big.int Error"))
				return
			}
			cfxto := cfxaddress.MustNewFromBase32(Msg.To)
			hash, err := acc.CFX_bc_EventSafeTransferFrom(int64DeNonce, int64DeLifeTime, string(DeFrom), string(key), cfxto.MustGetCommonAddress(), ID, AMOUNT, ContractAddressMap[projectName], cfxclient2RPC)
			key = nil
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			ctx.Write([]byte(hash))

			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
}
func CFX_1155TransferFrom(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.TransferFrom_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeNonce, err := acc.PrivateDecode(Msg.Nonce, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeLifeTime, err := acc.PrivateDecode(Msg.LifeTime, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DePassword, err := acc.PrivateDecode(Msg.Password, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeFrom, err := acc.PrivateDecode(Msg.From, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		int64DeNonce := int64(binary.BigEndian.Uint64(DeNonce))
		int64DeLifeTime := int64(binary.BigEndian.Uint64(DeLifeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			cfx2 := cfxaddress.MustNewFromBase32(string(DeFrom))
			key, str := Getdata_Catch(cfx2.MustGetCommonAddress().String(), string(DePassword), "cfx")
			if str != "" {
				ctx.Write([]byte(fmt.Sprint(str)))
				return
			}
			ID, bo := big.NewInt(1).SetString(Msg.Id, 10)
			if !bo {
				ctx.Write([]byte("Id to *big.int Error"))
				return
			}
			AMOUNT := big.NewInt(1)

			cfxto := cfxaddress.MustNewFromBase32(Msg.To)
			hash, err := acc.CFX_bc_EventSafeTransferFrom(int64DeNonce, int64DeLifeTime, string(DeFrom), string(key), cfxto.MustGetCommonAddress(), ID, AMOUNT, ContractAddressMap[projectName], cfxclient2RPC)
			key = nil
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			ctx.Write([]byte(hash))

			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
}
func CFX_1155FreeMintNFT(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.UserNFT1155AdminCreateNFT_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeNonce, err := acc.PrivateDecode(Msg.Nonce, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeLifeTime, err := acc.PrivateDecode(Msg.LifeTime, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DePassword, err := acc.PrivateDecode(Msg.Password, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeFrom, err := acc.PrivateDecode(Msg.From, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeTo, err := acc.PrivateDecode(Msg.To, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeNumber, err := acc.PrivateDecode(Msg.Number, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeCreator, err := acc.PrivateDecode(Msg.Creator, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		int64DeNonce := int64(binary.BigEndian.Uint64(DeNonce))
		int64DeLifeTime := int64(binary.BigEndian.Uint64(DeLifeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			cfx := cfxaddress.MustNewFromBase32(string(DeFrom))
			BI := big.NewInt(0)
			BNumber, boo := BI.SetString(string(DeNumber), 10)
			if !boo {
				ctx.Write([]byte("err big.Int SetString"))
				return
			}

			key, str := Getdata_Catch(cfx.MustGetCommonAddress().String(), string(DePassword), "cfx")
			// key, str := Getdata_Catch(cfx.MustGetCommonAddress().String(), string(DePassword))
			if str != "" {
				ctx.Write([]byte(fmt.Sprint(str)))
				return
			}
			// fmt.Println("Deto", string(DeTo), string(DeCreator), Msg.Nfturi, string(Msg.To))
			hash, err := acc.CFX_bc_FreeMintNFT1155(int64DeNonce, int64DeLifeTime, BNumber, string(DeFrom), string(key), string(DeTo), ContractAddressMap[projectName], common.HexToAddress(string(DeCreator)), Msg.Nfturi, cfxclient2RPC)
			key = nil
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			ctx.WriteString(hash)

			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
	}
}
func CFX_1155SetEventDetail(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.UserNFT1155AdminSetEventDetail_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeNonce, err := acc.PrivateDecode(Msg.Nonce, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeLifeTime, err := acc.PrivateDecode(Msg.LifeTime, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DePassword, err := acc.PrivateDecode(Msg.Password, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		int64DeNonce := int64(binary.BigEndian.Uint64(DeNonce))
		int64DeLifeTime := int64(binary.BigEndian.Uint64(DeLifeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			cfx := cfxaddress.MustNewFromBase32(Msg.From)
			BI := big.NewInt(0)
			ID, boo := BI.SetString(Msg.ID, 10)
			if !boo {
				ctx.Write([]byte("err big.Int SetString"))
				return
			}

			key, str := Getdata_Catch(cfx.MustGetCommonAddress().String(), string(DePassword), "cfx")
			// key, str := Getdata_Catch(cfx.MustGetCommonAddress().String(), string(DePassword))
			if str != "" {
				ctx.Write([]byte(fmt.Sprint(str)))
				return
			}
			// fmt.Println("Deto", string(DeTo), string(DeCreator), Msg.Nfturi, string(Msg.To))
			hash, err := acc.CFX_bc_SetEventDetails(int64DeNonce, int64DeLifeTime, ID, Msg.From, string(key), Msg.EventName, Msg.Organization, Msg.Logo, Msg.Description, ContractAddressMap[projectName], cfxclient2RPC)
			key = nil
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			ctx.WriteString(hash)

			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
	}
}

// 白名单
func CFX_1155SetSponrs(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.ContractDFWhitelist_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeNonce, err := acc.PrivateDecode(Msg.Nonce, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeLifeTime, err := acc.PrivateDecode(Msg.LifeTime, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DePassword, err := acc.PrivateDecode(Msg.Password, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeFrom, err := acc.PrivateDecode(Msg.From, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		int64DeNonce := int64(binary.BigEndian.Uint64(DeNonce))
		int64DeLifeTime := int64(binary.BigEndian.Uint64(DeLifeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			cfx := cfxaddress.MustNewFromBase32(string(DeFrom))

			key, str := Getdata_Catch(cfx.MustGetCommonAddress().String(), string(DePassword), "cfx")
			// key, str := Getdata_Catch(cfx.MustGetCommonAddress().String(), string(DePassword))
			if str != "" {
				ctx.Write([]byte(fmt.Sprint(str)))
				return
			}
			var ACCOUNTS []common.Address
			for i := 0; i < len(Msg.Accounts); i++ {
				cfx := cfxaddress.MustNewFromBase32(Msg.Accounts[i])
				ACCOUNTS = append(ACCOUNTS, cfx.MustGetCommonAddress())
			}
			hash, err := acc.CFX_bc_SetSponsors(int64DeNonce, int64DeLifeTime, string(DeFrom), string(key), ACCOUNTS, ContractAddressMap[projectName], cfxclient2RPC)
			key = nil
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			ctx.Write([]byte(hash))

			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
	}
}

// 域名服务
func CFX_DomainDNS(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.DomainDNS_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			// fmt.Println(Msg.DomianName, ContractAddressMap[projectName])
			owneraddress, _ := acc.CFX_Domian_DNS(Msg.DomianName, ContractAddressMap[projectName], cfxclientRPC)
			// fmt.Println(owneraddress.String())
			// if err != nil {
			// 	fmt.Println(err.Error())
			// 	ctx.Write([]byte(err.Error()))
			// 	return
			// }
			ctx.WriteString(cfxaddress.MustNewFromCommon(owneraddress, CFXNetID).String())
			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
}
func CFX_UserNFTsDNS(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.DomainUserNFTsDNS_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放

			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			DomianName, IDs, err := acc.CFX_Domian_UserNFTsDNS(common.HexToAddress(Msg.Account), ContractAddressMap[projectName], cfxclientRPC)
			if err != nil {
				fmt.Println(err.Error())
				ctx.Write([]byte(err.Error()))
				return
			}
			var ResList acc.DomainUserNFTsDNS_RESMessage
			ResList.Number = len(IDs)
			if len(IDs) == 0 {
				// var res acc.NFTsDNS_RESMessage
				// res.Domainname = ""
				// res.NFTID = ""
				// ResList.Data = append(ResList.Data, res)
			} else {
				for i := 0; i < len(IDs); i++ {
					var res acc.NFTsDNS_RESMessage
					res.Domainname = DomianName[i]
					res.NFTID = IDs[i].String()
					ResList.Data = append(ResList.Data, res)
				}
			}

			buu, err := json.Marshal(ResList)
			if err != nil {
				ctx.Write([]byte("json.Marshal(ResList)" + err.Error()))
				return
			}
			ctx.Write(buu)
			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
}
func CFX_DomainTimes(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.DomainTimes_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			var IDS []*big.Int
			for i := 0; i < len(Msg.IDs); i++ {
				BI := big.NewInt(0)
				BNi, boo := BI.SetString(Msg.IDs[i], 10)
				if !boo {
					ctx.Write([]byte("err big.Int SetString"))
					return
				}
				IDS = append(IDS, BNi)
			}
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			DomianNameTimes, err := acc.CFX_Domian_DomainTimes(IDS, ContractAddressMap[projectName], cfxclientRPC)
			if err != nil {
				fmt.Println(err.Error())
				ctx.Write([]byte(err.Error()))
				return
			}
			var ResList acc.DomainTimes_RESMessage
			ResList.Number = len(DomianNameTimes)
			if len(DomianNameTimes) == 0 {

			} else {
				for i := 0; i < len(DomianNameTimes); i++ {
					var res acc.DomainTime_RESMessage
					res.Times = DomianNameTimes[i].String()
					res.NFTID = Msg.IDs[i]
					ResList.Data = append(ResList.Data, res)
				}
			}

			buu, err := json.Marshal(ResList)
			if err != nil {
				ctx.Write([]byte("json.Marshal(ResList)" + err.Error()))
				return
			}
			ctx.Write(buu)
			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
}

func CFX_AddDomainTime(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.DomainAddTimes_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeNonce, err := acc.PrivateDecode(Msg.Nonce, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeLifeTime, err := acc.PrivateDecode(Msg.LifeTime, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DePassword, err := acc.PrivateDecode(Msg.Password, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		int64DeNonce := int64(binary.BigEndian.Uint64(DeNonce))
		int64DeLifeTime := int64(binary.BigEndian.Uint64(DeLifeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			var IDS []*big.Int
			for i := 0; i < len(Msg.IDs); i++ {
				BI := big.NewInt(0)
				BNi, boo := BI.SetString(Msg.IDs[i], 10)
				if !boo {
					ctx.Write([]byte("err big.Int SetString"))
					return
				}
				IDS = append(IDS, BNi)
			}
			var DAYS []*big.Int
			for i := 0; i < len(Msg.Numbers); i++ {
				BI := big.NewInt(0)
				BNi, boo := BI.SetString(Msg.Numbers[i], 10)
				if !boo {
					ctx.Write([]byte("err big.Int SetString"))
					return
				}
				DAYS = append(DAYS, BNi)
			}
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			cfx := cfxaddress.MustNewFromBase32(string(Msg.From))
			key, str := Getdata_Catch(cfx.MustGetCommonAddress().String(), string(DePassword), "cfx")
			if str != "" {
				ctx.Write([]byte(fmt.Sprint(str)))
				return
			}

			Hash, err := acc.CFX_Domian_AddDomainTime(int64DeNonce, int64DeLifeTime, IDS, Msg.From, string(key), DAYS, ContractAddressMap[projectName], cfxclient2RPC)
			key = nil
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			ctx.WriteString(Hash)
			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
	}
}

func CFX_RushToRegisterDomain(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.TransferFrom_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeNonce, err := acc.PrivateDecode(Msg.Nonce, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeLifeTime, err := acc.PrivateDecode(Msg.LifeTime, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DePassword, err := acc.PrivateDecode(Msg.Password, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeFrom, err := acc.PrivateDecode(Msg.From, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		int64DeNonce := int64(binary.BigEndian.Uint64(DeNonce))
		int64DeLifeTime := int64(binary.BigEndian.Uint64(DeLifeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			cfx2 := cfxaddress.MustNewFromBase32(string(DeFrom))
			key, str := Getdata_Catch(cfx2.MustGetCommonAddress().String(), string(DePassword), "cfx")
			if str != "" {
				ctx.Write([]byte(fmt.Sprint(str)))
				return
			}
			ID, bo := big.NewInt(1).SetString(Msg.Id, 10)
			if !bo {
				ctx.Write([]byte("Id to *big.int Error"))
				return
			}
			cfxto := cfxaddress.MustNewFromBase32(Msg.To)
			hash, err := acc.CFX_Domian_RushToRegisterDomain(int64DeNonce, int64DeLifeTime, ID, string(DeFrom), string(key), cfxto.MustGetCommonAddress(), ContractAddressMap[projectName], cfxclient2RPC)
			key = nil
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			ctx.Write([]byte(hash))

			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
}

// //////////////////////////////FSC///////////////////////////////////////////
func CFX_FSC_SetData(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.FSCsetdata_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DePassword, err := acc.PrivateDecode(Msg.Password, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeFrom, err := acc.PrivateDecode(Msg.From, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			cfx2 := cfxaddress.MustNewFromBase32(string(DeFrom))
			key, str := Getdata_Catch(cfx2.MustGetCommonAddress().String(), string(DePassword), "cfx")
			if str != "" {
				ctx.Write([]byte(fmt.Sprint(str)))
				return
			}
			cfxto := cfxaddress.MustNewFromBase32(Msg.To)
			hashs, err := acc.FSC_SetData(string(key), cfx2, cfxto, Msg.Data, cfxclient2RPC)
			key = nil
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			var reshash string
			for i := 0; i < len(hashs); i++ {
				reshash += hashs[i] + ","
			}
			reshash = reshash[:len(reshash)-1]
			ctx.WriteString(reshash) //多个hash,号隔开
			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
}

// ///////////////////////////ETH CHAIN//////////////////////////////////////
func ETH_TotalSupply(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.UserRegit_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		// fmt.Println("DeAppid=", DeAppid)
		// fmt.Println("APPIDdict[projectName]=", APPIDdict[projectName])
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeRPCnode, err := acc.PrivateDecode(Msg.Data, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			// fmt.Println(1)
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			var clientRPC *ethclient.Client
			if string(DeRPCnode) == "eth" {
				clientRPC = ethclientRPC
			} else if string(DeRPCnode) == "bsc" {
				clientRPC = bscclientRPC
			} else if string(DeRPCnode) == "arb" {
				clientRPC = arbclientRPC
			} else if string(DeRPCnode) == "csuat" {
				clientRPC = csuatclientRPC
				fmt.Println(string(DeRPCnode))
			} else {
				ctx.Write([]byte("ChainType is null"))
				return
			}
			total, err := acc.ETH_bc_NFT_INDEX(ContractAddressMap[projectName], clientRPC)
			// fmt.Println(total)
			// fmt.Println(err)
			if err != nil {
				// fmt.Println(total)
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			ctx.Write([]byte(total.String()))

			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
}
func ETH_AdminCreateNFT(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.AdminCreateNFT_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeNonce, err := acc.PrivateDecode(Msg.Nonce, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeLifeTime, err := acc.PrivateDecode(Msg.LifeTime, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DePassword, err := acc.PrivateDecode(Msg.Password, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeFrom, err := acc.PrivateDecode(Msg.From, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeTo, err := acc.PrivateDecode(Msg.To, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeChainType, err := acc.PrivateDecode(Msg.ChainType, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		int64DeNonce := int64(binary.BigEndian.Uint64(DeNonce))
		int64DeLifeTime := int64(binary.BigEndian.Uint64(DeLifeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			var clientRPC *ethclient.Client
			if string(DeChainType) == "eth" {
				clientRPC = ethclientRPC
			} else if string(DeChainType) == "bsc" {
				clientRPC = bscclientRPC
			} else if string(DeChainType) == "arb" {
				clientRPC = arbclientRPC
			} else if string(DeChainType) == "csuat" {
				clientRPC = csuatclientRPC
				fmt.Println(string(DeChainType))
			} else {
				ctx.Write([]byte("ChainType is null"))
				return
			}
			key, str := Getdata_Catch(string(DeFrom), string(DePassword), "eth")
			if str != "" {
				ctx.Write([]byte(fmt.Sprint(str)))
				return
			}
			fmt.Println(string(DeChainType))
			hash, err := acc.ETH_bc_AdminCreateNFT(int64DeNonce, int64DeLifeTime, common.HexToAddress(string(DeFrom)), common.HexToAddress(string(DeTo)), string(key), ContractAddressMap[projectName], clientRPC)
			key = nil
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			ctx.Write([]byte(hash))

			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
}
func ETH_AdminCreateNFTBatch(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.AdminCreateNFTBatch_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeNonce, err := acc.PrivateDecode(Msg.Nonce, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeLifeTime, err := acc.PrivateDecode(Msg.LifeTime, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DePassword, err := acc.PrivateDecode(Msg.Password, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeFrom, err := acc.PrivateDecode(Msg.From, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		DeChainType, err := acc.PrivateDecode(Msg.ChainType, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		int64DeNonce := int64(binary.BigEndian.Uint64(DeNonce))
		int64DeLifeTime := int64(binary.BigEndian.Uint64(DeLifeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			var clientRPC *ethclient.Client
			if string(DeChainType) == "eth" {
				clientRPC = ethclientRPC
			} else if string(DeChainType) == "bsc" {
				clientRPC = bscclientRPC
			} else if string(DeChainType) == "arb" {
				clientRPC = arbclientRPC
			} else {
				ctx.Write([]byte("ChainType is null"))
				return
			}
			//tos
			var DeTos []common.Address
			for i := 0; i < len(Msg.Tos); i++ {
				DeTos = append(DeTos, common.HexToAddress(Msg.Tos[i]))
			}
			key, str := Getdata_Catch(string(DeFrom), string(DePassword), "eth")
			if str != "" {
				ctx.Write([]byte(fmt.Sprint(str)))
				return
			}
			fmt.Println(string(DeChainType))
			hash, err := acc.ETH_bc_AdminCreateNFTBatch(int64DeNonce, int64DeLifeTime, common.HexToAddress(string(DeFrom)), DeTos, string(key), ContractAddressMap[projectName], clientRPC)
			key = nil
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			ctx.Write([]byte(hash))

			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
}
func ETH_AdminTransferNFTBatch(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.AdminTransferNFTBatch_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeNonce, err := acc.PrivateDecode(Msg.Nonce, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeLifeTime, err := acc.PrivateDecode(Msg.LifeTime, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DePassword, err := acc.PrivateDecode(Msg.Password, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeFrom, err := acc.PrivateDecode(Msg.From, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		DeChainType, err := acc.PrivateDecode(Msg.ChainType, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		int64DeNonce := int64(binary.BigEndian.Uint64(DeNonce))
		int64DeLifeTime := int64(binary.BigEndian.Uint64(DeLifeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			var clientRPC *ethclient.Client
			if string(DeChainType) == "eth" {
				clientRPC = ethclientRPC
			} else if string(DeChainType) == "bsc" {
				clientRPC = bscclientRPC
			} else if string(DeChainType) == "arb" {
				clientRPC = arbclientRPC
			} else {
				ctx.Write([]byte("ChainType is null"))
				return
			}
			//tos
			var DeTos []common.Address
			for i := 0; i < len(Msg.Tos); i++ {
				DeTos = append(DeTos, common.HexToAddress(Msg.Tos[i]))
			}
			//ids
			var ids []*big.Int

			for i := 0; i < len(Msg.Ids); i++ {
				var bg *big.Int = big.NewInt(1)
				bi, bo := (bg).SetString(Msg.Ids[i], 10)
				if !bo {
					ctx.Write([]byte("Msg.Ids[i] to *big.int Error"))
					return
				}
				ids = append(ids, bi)
			}
			key, str := Getdata_Catch(string(DeFrom), string(DePassword), "eth")
			if str != "" {
				ctx.Write([]byte(fmt.Sprint(str)))
				return
			}
			fmt.Println(string(DeChainType))
			hash, err := acc.ETH_bc_AdminTransferNFTBatch(int64DeNonce, int64DeLifeTime, common.HexToAddress(string(DeFrom)), DeTos, string(key), ids, ContractAddressMap[projectName], clientRPC)
			key = nil
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			ctx.Write([]byte(hash))

			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
}
func ETH_TransferFrom(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.TransferFrom_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeNonce, err := acc.PrivateDecode(Msg.Nonce, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeLifeTime, err := acc.PrivateDecode(Msg.LifeTime, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DePassword, err := acc.PrivateDecode(Msg.Password, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeFrom, err := acc.PrivateDecode(Msg.From, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		DeChainType, err := acc.PrivateDecode(Msg.ChainType, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		int64DeNonce := int64(binary.BigEndian.Uint64(DeNonce))
		int64DeLifeTime := int64(binary.BigEndian.Uint64(DeLifeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			var clientRPC *ethclient.Client
			if string(DeChainType) == "eth" {
				clientRPC = ethclientRPC
			} else if string(DeChainType) == "bsc" {
				clientRPC = bscclientRPC
			} else if string(DeChainType) == "arb" {
				clientRPC = arbclientRPC
			} else {
				ctx.Write([]byte("ChainType is null"))
				return
			}
			key, str := Getdata_Catch(string(DeFrom), string(DePassword), "eth")
			if str != "" {
				ctx.Write([]byte(fmt.Sprint(str)))
				return
			}
			fmt.Println(string(DeChainType))
			ID, bo := big.NewInt(1).SetString(Msg.Id, 10)
			if !bo {
				ctx.Write([]byte("Id to *big.int Error"))
				return
			}
			hash, err := acc.ETH_bc_TransferFrom(int64DeNonce, int64DeLifeTime, common.HexToAddress(string(DeFrom)), common.HexToAddress(Msg.To), string(key), ID, ContractAddressMap[projectName], clientRPC)
			key = nil
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			ctx.Write([]byte(hash))

			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
}
func ETH_Burn(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.TransferFrom_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeNonce, err := acc.PrivateDecode(Msg.Nonce, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeLifeTime, err := acc.PrivateDecode(Msg.LifeTime, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DePassword, err := acc.PrivateDecode(Msg.Password, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeFrom, err := acc.PrivateDecode(Msg.From, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		DeChainType, err := acc.PrivateDecode(Msg.ChainType, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		int64DeNonce := int64(binary.BigEndian.Uint64(DeNonce))
		int64DeLifeTime := int64(binary.BigEndian.Uint64(DeLifeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			var clientRPC *ethclient.Client
			if string(DeChainType) == "eth" {
				clientRPC = ethclientRPC
			} else if string(DeChainType) == "bsc" {
				clientRPC = bscclientRPC
			} else if string(DeChainType) == "arb" {
				clientRPC = arbclientRPC
			} else {
				ctx.Write([]byte("ChainType is null"))
				return
			}
			key, str := Getdata_Catch(string(DeFrom), string(DePassword), "eth")
			if str != "" {
				ctx.Write([]byte(fmt.Sprint(str)))
				return
			}
			fmt.Println(string(DeChainType))
			ID, bo := big.NewInt(1).SetString(Msg.Id, 10)
			if !bo {
				ctx.Write([]byte("Id to *big.int Error"))
				return
			}
			hash, err := acc.ETH_bc_Burn(int64DeNonce, int64DeLifeTime, common.HexToAddress(string(DeFrom)), ID, string(key), ContractAddressMap[projectName], clientRPC)
			key = nil
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			ctx.Write([]byte(hash))

			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
}
func ETH_Approve(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.TransferFrom_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeNonce, err := acc.PrivateDecode(Msg.Nonce, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeLifeTime, err := acc.PrivateDecode(Msg.LifeTime, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DePassword, err := acc.PrivateDecode(Msg.Password, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeFrom, err := acc.PrivateDecode(Msg.From, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		DeChainType, err := acc.PrivateDecode(Msg.ChainType, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		int64DeNonce := int64(binary.BigEndian.Uint64(DeNonce))
		int64DeLifeTime := int64(binary.BigEndian.Uint64(DeLifeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			var clientRPC *ethclient.Client
			if string(DeChainType) == "eth" {
				clientRPC = ethclientRPC
			} else if string(DeChainType) == "bsc" {
				clientRPC = bscclientRPC
			} else if string(DeChainType) == "arb" {
				clientRPC = arbclientRPC
			} else {
				ctx.Write([]byte("ChainType is null"))
				return
			}
			key, str := Getdata_Catch(string(DeFrom), string(DePassword), "eth")
			if str != "" {
				ctx.Write([]byte(fmt.Sprint(str)))
				return
			}
			fmt.Println(string(DeChainType))
			ID, bo := big.NewInt(1).SetString(Msg.Id, 10)
			if !bo {
				ctx.Write([]byte("Id to *big.int Error"))
				return
			}
			hash, err := acc.ETH_bc_approve(int64DeNonce, int64DeLifeTime, common.HexToAddress(string(DeFrom)), common.HexToAddress(Msg.To), string(key), ID, ContractAddressMap[projectName], clientRPC)
			key = nil
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			ctx.Write([]byte(hash))

			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
}
func ETH_BurnBatch(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.AdminTransferNFTBatch_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeNonce, err := acc.PrivateDecode(Msg.Nonce, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeLifeTime, err := acc.PrivateDecode(Msg.LifeTime, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DePassword, err := acc.PrivateDecode(Msg.Password, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeFrom, err := acc.PrivateDecode(Msg.From, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		DeChainType, err := acc.PrivateDecode(Msg.ChainType, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		int64DeNonce := int64(binary.BigEndian.Uint64(DeNonce))
		int64DeLifeTime := int64(binary.BigEndian.Uint64(DeLifeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			var clientRPC *ethclient.Client
			if string(DeChainType) == "eth" {
				clientRPC = ethclientRPC
			} else if string(DeChainType) == "bsc" {
				clientRPC = bscclientRPC
			} else if string(DeChainType) == "arb" {
				clientRPC = arbclientRPC
			} else {
				ctx.Write([]byte("ChainType is null"))
				return
			}

			//ids
			var ids []*big.Int

			for i := 0; i < len(Msg.Ids); i++ {
				var bg *big.Int = big.NewInt(1)
				bi, bo := (bg).SetString(Msg.Ids[i], 10)
				if !bo {
					ctx.Write([]byte("Msg.Ids[i] to *big.int Error"))
					return
				}
				ids = append(ids, bi)
			}
			key, str := Getdata_Catch(string(DeFrom), string(DePassword), "eth")
			if str != "" {
				ctx.Write([]byte(fmt.Sprint(str)))
				return
			}
			fmt.Println(string(DeChainType))
			// fmt.Println(string(key))
			hash, err := acc.ETH_bc_BurnBatch(int64DeNonce, int64DeLifeTime, common.HexToAddress(string(DeFrom)), string(key), ids, ContractAddressMap[projectName], clientRPC)
			key = nil
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			ctx.Write([]byte(hash))

			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
}
func ETH_UserNFTs(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.UserNFTs_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeFrom, err := acc.PrivateDecode(Msg.From, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeChainType, err := acc.PrivateDecode(Msg.ChainType, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			var clientRPC *ethclient.Client
			if string(DeChainType) == "eth" {
				clientRPC = ethclientRPC
			} else if string(DeChainType) == "bsc" {
				clientRPC = bscclientRPC
			} else if string(DeChainType) == "arb" {
				clientRPC = arbclientRPC
			} else {
				ctx.Write([]byte("ChainType is null"))
				return
			}

			// fmt.Println(1)DePassword
			nfts, err := acc.ETH_bc_userNFTs(common.HexToAddress(string(DeFrom)), ContractAddressMap[projectName], clientRPC)
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			if len(nfts) > 0 {
				var nftsj []string
				for i := 0; i < len(nfts); i++ {
					nftsj = append(nftsj, nfts[i].String())
				}
				ctx.WriteString(strings.Join(nftsj, ","))
			} else {
				ctx.Write([]byte(""))
			}

			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
}
func ETH_TokenUri(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.UserNFTUri_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeID, err := acc.PrivateDecode(Msg.ID, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeChainType, err := acc.PrivateDecode(Msg.ChainType, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			var clientRPC *ethclient.Client
			if string(DeChainType) == "eth" {
				clientRPC = ethclientRPC
			} else if string(DeChainType) == "bsc" {
				clientRPC = bscclientRPC
			} else if string(DeChainType) == "arb" {
				clientRPC = arbclientRPC
			} else {
				ctx.Write([]byte("ChainType is null"))
				return
			}
			BI := big.NewInt(1)
			BG, boo := BI.SetString(string(DeID), 10)
			if !boo {
				ctx.Write([]byte("err big.Int SetString"))
				return
			}
			// fmt.Println(1)DePassword
			uri, err := acc.ETH_bc_tokenURL(BG, ContractAddressMap[projectName], clientRPC)
			if err != nil {
				ctx.Write([]byte(err.Error()))
				return
			}
			ctx.WriteString(uri)
			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
}
func ETH_OwnerOf(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.UserNFTUri_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeID, err := acc.PrivateDecode(Msg.ID, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeChainType, err := acc.PrivateDecode(Msg.ChainType, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			var clientRPC *ethclient.Client
			if string(DeChainType) == "eth" {
				clientRPC = ethclientRPC
			} else if string(DeChainType) == "bsc" {
				clientRPC = bscclientRPC
			} else if string(DeChainType) == "arb" {
				clientRPC = arbclientRPC
			} else {
				ctx.Write([]byte("ChainType is null"))
				return
			}
			var BI big.Int
			BG, boo := BI.SetString(string(DeID), 10)
			if !boo {
				ctx.Write([]byte("err big.Int SetString"))
				return
			}
			// fmt.Println(1)DePassword
			ownerAddress, err := acc.ETH_bc_ownerOf(BG, ContractAddressMap[projectName], clientRPC)
			if err != nil {
				ctx.Write([]byte(err.Error()))
				return
			}
			ctx.WriteString(ownerAddress)
			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
}
func ETH_ApproveForAll(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &acc.ApproveAll_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := ProjectNamedict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := ProjectPublickeyCatchdict[projectName]
		// fmt.Println(string(prvCa))
		if prvCa == nil {
			ctx.Write([]byte("no ProjectPublickeyCatchdict"))
			return
		}
		//解码
		DeAppid, err := acc.PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := acc.PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := acc.PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeNonce, err := acc.PrivateDecode(Msg.Nonce, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeLifeTime, err := acc.PrivateDecode(Msg.LifeTime, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DePassword, err := acc.PrivateDecode(Msg.Password, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeFrom, err := acc.PrivateDecode(Msg.From, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeChainType, err := acc.PrivateDecode(Msg.ChainType, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		int64DeNonce := int64(binary.BigEndian.Uint64(DeNonce))
		int64DeLifeTime := int64(binary.BigEndian.Uint64(DeLifeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -10 {
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			var clientRPC *ethclient.Client
			if string(DeChainType) == "eth" {
				clientRPC = ethclientRPC
			} else if string(DeChainType) == "bsc" {
				clientRPC = bscclientRPC
			} else if string(DeChainType) == "arb" {
				clientRPC = arbclientRPC
			} else {
				ctx.Write([]byte("ChainType is null"))
				return
			}
			key, str := Getdata_Catch(string(DeFrom), string(DePassword), "eth")
			if str != "" {
				ctx.Write([]byte(fmt.Sprint(str)))
				return
			}
			fmt.Println(string(DeChainType))
			IsApprove := false
			if Msg.IsApprove == "true" {
				IsApprove = true
			}
			hash, err := acc.ETH_bc_setApprovalForAll(int64DeNonce, int64DeLifeTime, common.HexToAddress(string(DeFrom)), common.HexToAddress(Msg.To), string(key), IsApprove, ContractAddressMap[projectName], clientRPC)
			key = nil
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			ctx.Write([]byte(hash))

			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
}

/////////////////////////////COMMON FUNCTION//////////////////////////////////////

func Getdata_Catch(address string, password string, addrrssType string) ([]byte, string) {
	var keydata interface{}
	var found bool
	if addrrssType == "cfx" {
		keydata, found = GetCFXDataCatch.Get(address)
	} else {
		keydata, found = GetETHDataCatch.Get(address)
	}
	if found {
		Dat := keydata.(KeyData_Message).data
		Key := keydata.(KeyData_Message).key
		//更新Tak文件
		//AES 解ECC
		massage, err := hex.DecodeString(Key)
		if err != nil {
			return nil, fmt.Sprint(err)
		}
		//指定密钥
		bu := []byte(acc.CalculateHashcode(password))
		bu = bu[:32]
		key := bu
		//加密
		DecodeECCKey := acc.AEC_CRT_Crypt(massage, key) //
		//解码
		priKey, err := crypto.HexToECDSA(string(DecodeECCKey))
		if err != nil {
			return nil, fmt.Sprint(err)
		}
		priKeyecies := ecies.ImportECDSA(priKey)
		//获得分片
		RSAprv, RSApuk := acc.GenerateRsaKey(2048)
		//发送获取请求addrrssType=cfx/eth
		body := HalfPrvDataPost(IPandPort, "GetHalfPrvData", APPID_PrvKeyPiceServer, address, addrrssType, string(RSApuk), "ghpd")
		// fmt.Println(string(body))
		if string(body) == "NONE" {
			fmt.Println("GetHalfPrvDataPost 失败！")
			return nil, "GetHalfPrvDataPost 失败！"
		}
		block, _ := pem.Decode(RSAprv)
		// fmt.Println(block)
		//3. 使用x509将编码之后的私钥解析出来
		privateKey, err3 := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err3 != nil {
			fmt.Println(err3.Error())
			return nil, err3.Error()
		}
		encode2half, err := acc.PrivateDecode(body, privateKey)
		if err != nil {
			return nil, fmt.Sprint(err)
		}
		// fmt.Println("encode2half", string(encode2half))
		end1, err := hex.DecodeString(Dat)
		end2, err := hex.DecodeString(string(encode2half))
		if err != nil {
			return nil, fmt.Sprint(err)
		}
		relyData := acc.BytesCombine1(end1[:113], end2)
		// fmt.Println("relyData", string(relyData))
		deblockPrivateKey, err := acc.ECCDecrypt(relyData, *priKeyecies)
		if err != nil {
			return nil, fmt.Sprint(err)
		}
		return deblockPrivateKey, ""
	} else {
		fmt.Println("NO DB")
		return nil, "NO DB"
	}
	// wg.Done()
}

// post 服务
func HalfPrvDataPost(thurl string, actionName string, myappid string, address string, ETHaddress string, data string, flag string) []byte {
	now := uint64(time.Now().Unix())    //获取当前时间
	by := make([]byte, 8)               //建立数组
	binary.BigEndian.PutUint64(by, now) //uint64转数组
	//加密数据
	src_appid := acc.PublicEncode([]byte(myappid), PUK)
	src_mytime := acc.PublicEncode([]byte(by), PUK)
	src_address := acc.PublicEncode([]byte(address), PUK)
	src_ETHaddress := acc.PublicEncode([]byte(ETHaddress), PUK)
	src_data, err := acc.PublicEncodeLong([]byte(data), PUK)
	if err != nil {
		return []byte("publicEncodeLong error")
	}
	src_token := acc.PublicEncode([]byte(fmt.Sprint(time.Now().UnixNano())+myappid+flag), PUK)
	//post请求提交json数据
	messages := Prvhalfdata_Message{[]byte(acc.CalculateHashcode(myappid)), src_appid, src_mytime, src_token, src_address, src_ETHaddress, src_data}
	ba, err := json.Marshal(messages)
	if err != nil {
		return []byte("json.Marshal error")
	}

	resp, err := HalfPrvDataPostclient.Post(thurl+"/"+actionName+"", "application/json", bytes.NewBuffer([]byte(ba)))
	if err != nil {
		return []byte("http error:" + fmt.Sprint(err))
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte("ReadAll error")
	}
	if err != nil {
		panic(err)
	}
	return body
}

// CFX_NewContractSettingData
func CFX_NewContractSettingData(ctx iris.Context) {

}
