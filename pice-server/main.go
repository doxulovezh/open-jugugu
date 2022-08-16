package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	acc "web/util"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	_ "github.com/go-sql-driver/mysql"
	"github.com/kataras/iris/v12"
	"github.com/patrickmn/go-cache" // 使用前先import包
)

var APPID_PrvKeyPiceServer string = "123456"
var ca1 []byte
var ca2 []byte
var HEXprv string = "123456"
var GloKS *keystore.KeyStore
var (
	DB       *sql.DB
	GlobalDB *sql.DB
)
var wg sync.WaitGroup

type Prvhalfdata_Message struct {
	Sha256Value []byte `json:"sha256value"`
	Appid       []byte `json:"appid"`
	Time        []byte `json:"emit"`
	Token       []byte `json:"token"`
	Address     []byte `json:"address"`
	ETHAddress  []byte `json:"ethaddress"`
	Data        []byte `json:"data"`
	Flag        []byte `json:"flag"`
}

type setting struct {
	ServerIP   string `json:"serverIP"`
	ServerPort string `json:"serverPort"`
	NodeURL    string `json:"nodeURL"`
}

func lode1(cach string) ([]byte, error) {
	file, err := os.Open(cach)
	if err != nil {
		return []byte(""), err
	}
	stat, _ := file.Stat()
	data := make([]byte, stat.Size())
	file.Read(data)
	file.Close()
	key := []byte("123456")
	// fmt.Println(len(key))
	return AEC_CRT_Crypt(data, key), nil
}

var APPIDdict map[string]string            //定义dict为map类型
var Projectdict map[string]string          //定义dict为map类型
var catchdict map[string]*rsa.PrivateKey   //定义dict为map类型
var catchdictPuk map[string]*rsa.PublicKey //定义dict为map类型
var Tokencatch *cache.Cache
var CFXDATACatch *cache.Cache
var ETHDATACatch *cache.Cache
var prk22 *ecies.PrivateKey
var puk22 ecies.PublicKey
var app *iris.Application
var GetDataStm *sql.Stmt
var GetDataStmETH *sql.Stmt
var SetDataStm *sql.Stmt
var GetDataALLStm *sql.Stmt

// var DeletAccountDataStm *sql.Stmt
var ServerIP string
var ServerPort string

func main() {
	InitServerSetting()
	//ECC
	priKey, err := crypto.HexToECDSA(HEXprv)
	if err != nil {
		panic(err)
	}
	prk22 = ecies.ImportECDSA(priKey)
	puk22 = prk22.PublicKey
	//token catch
	// 创建一个cache对象，默认ttl 5分钟，每10分钟对过期数据进行一次清理
	Tokencatch = cache.New(2*time.Minute, 2*time.Minute)
	CFXDATACatch = cache.New(cache.NoExpiration, cache.NoExpiration)
	ETHDATACatch = cache.New(cache.NoExpiration, cache.NoExpiration)
	//SQL
	Projectdict = make(map[string]string)                                   //让dict可编辑
	catchdict = make(map[string]*rsa.PrivateKey)                            //让dict可编辑
	catchdictPuk = make(map[string]*rsa.PublicKey)                          //让dict可编辑
	APPIDdict = make(map[string]string)                                     //让dict可编辑
	Projectdict[acc.SHA256_strReturnString(APPID_PrvKeyPiceServer)] = "小红花" //加值1  sha256(APPID)=>proName
	ca, err := lode1("catch1.dll")
	ca2, err := lode1("catch2.dll")
	if err != nil {
		panic(err)
	}
	//2. 将得到的字符串进行pem解码
	block, _ := pem.Decode(ca)
	//3. 使用x509将编码之后的私钥解析出来
	privateKey, err3 := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err3 != nil {
		panic(err3)
	}
	//2. 将得到的字符串进行pem解码
	block2, _ := pem.Decode(ca2)
	//3. 使用x509将编码之后的私钥解析出来
	//3. 使用x509将编码之后的公钥解析出来
	pubInterface, err2 := x509.ParsePKIXPublicKey(block2.Bytes)
	if err2 != nil {
		panic(err2)
	}
	pubKey := pubInterface.(*rsa.PublicKey)
	catchdict["小红花"] = privateKey
	catchdictPuk["小红花"] = pubKey
	APPIDdict["小红花"] = APPID_PrvKeyPiceServer
	//SQL
	conn := "user:123456@tcp(127.0.0.1:3306)/tikverse?charset=utf8"
	dbg, err := sql.Open("mysql", conn)
	if err != nil {
		fmt.Println(err, "数据库链接错误")
		return
	} else {
		fmt.Println("数据库链接成功!")
	}
	GlobalDB = dbg
	InitStm()
	//全局缓存
	InitCatchSQL()
	//
	app = iris.New()
	// app.Use(CorsALL)
	// app.Get("/login", login)
	app.Post("/SetHalfPrvData", SetHalfPrvData)
	app.Post("/GetHalfPrvData", GetHalfPrvData)
	// app.Run(iris.Addr(":13143"), iris.WithoutServerError(iris.ErrServerClosed))
	// app.Listen(ServerIP+":"+ServerPort, iris.WithoutServerError(iris.ErrServerClosed))
	app.Run(iris.TLS(ServerIP+":"+ServerPort, "cas.clientservice.cer", "cas.clientservice.key"), iris.WithoutServerError(iris.ErrServerClosed))
}
func InitStm() {
	myGetDataStm, err := GlobalDB.Prepare("SELECT half_data.data FROM tikverse.half_data WHERE half_data.address=?")
	if err != nil {
		panic(err)
	}
	GetDataStm = myGetDataStm
	GetDataStmETH, err = GlobalDB.Prepare("SELECT half_data.data FROM tikverse.half_data WHERE half_data.ethaddress=?")
	if err != nil {
		panic(err)
	}
	SetDataStm, err = GlobalDB.Prepare("replace into half_data(half_data.address,half_data.ethaddress,half_data.data) VALUES(?,?,?)")
	if err != nil {
		panic(err)
	}
	//全局缓存
	GetDataALLStm, err = GlobalDB.Prepare("SELECT half_data.address,half_data.data,half_data.ethaddress FROM tikverse.half_data")
	if err != nil {
		panic(err)
	}
	// //删除
	// DeletAccountDataStm, err = GlobalDB.Prepare("DELETE FROM tikverse.half_data WHERE  half_data.address =?")
	// if err != nil {
	// 	fmt.Print(err.Error())
	// }

}
func InitCatchSQL() {
	res, err := GetDataALLStm.Query()
	if err != nil {
		panic(err)
	}
	defer res.Close()
	var cfxaddress string
	var Dat string
	var ethaddress string
	for res.Next() {
		res.Scan(&cfxaddress, &Dat, &ethaddress)
		CFXDATACatch.Set(cfxaddress, Dat, cache.NoExpiration)
		ETHDATACatch.Set(ethaddress, Dat, cache.NoExpiration)
	}
	fmt.Println("缓存SQL数据成功......")
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
	fmt.Println("load setting success!")
	fmt.Println("ServerIP:", ServerIP)
	fmt.Println("ServerPort:", ServerPort)

}
func login(ctx iris.Context) {
	ctx.WriteString("test 测试！")
}
func SetHalfPrvData(ctx iris.Context) {
	Msg := &Prvhalfdata_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := Projectdict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := catchdict[projectName]
		//解码
		DeAppid, err := PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		//
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		DeAddress, err := PrivateDecode(Msg.Address, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeETHAddress, err := PrivateDecode(Msg.ETHAddress, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeData, err := PrivateDecode(Msg.Data, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeFlag, err := PrivateDecode(Msg.Flag, prvCa)
		if err != nil {
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		now := time.Now().Unix()
		if now-int64Time < 120 || now-int64Time > -120 {
			//新注册校验
			if string(DeFlag) == "shpdreg" {
				_, found := CFXDATACatch.Get(acc.SHA256_strReturnString(string(DeAddress)))
				if found {
					ctx.WriteString("Same Address")
					return
				}
			} else if string(DeFlag) == "shpd" {
				_, found := CFXDATACatch.Get(acc.SHA256_strReturnString(string(DeAddress)))
				if found {
					ctx.WriteString("Same Address to modify by PRK")
					//删除
					//先删除
					// _, err = DeletAccountDataStm.Exec(acc.SHA256_strReturnString(string(DeAddress)))
					// if err != nil {
					// 	ctx.WriteString(err.Error())
					// 	return
					// }
					// return
				}
			}
			//ECC再次加密
			enData, err := ECCEncrypt(DeData, puk22)
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			//写入数据库
			var cfxaddress = acc.SHA256_strReturnString(string(DeAddress))
			var ethaddress = acc.SHA256_strReturnString(string(DeETHAddress))
			var Dat = hex.EncodeToString(enData)
			_, err = SetDataStm.Exec(cfxaddress, ethaddress, Dat)
			if err != nil {
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			CFXDATACatch.Set(cfxaddress, Dat, cache.NoExpiration)
			ETHDATACatch.Set(ethaddress, Dat, cache.NoExpiration)
			// wg.Done()
			// stm.Close()
			//加入已使用的token 防止重放
			Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
			ctx.Write([]byte("SHPDS"))
			app.Logger().Info("SetHalfPrvData")
			return
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// ctx.JSON(Msg)返回json

	}
}

var RES struct {
	date string
}

// 获取半密钥
func GetHalfPrvData(ctx iris.Context) {
	//获得传过来的  rsa puk
	Msg := &Prvhalfdata_Message{}
	if err := ctx.ReadJSON(Msg); err != nil {
		ctx.Write([]byte(fmt.Sprint(err)))
		return
	} else {
		//获得字典
		projectName := Projectdict[string(Msg.Sha256Value)]
		if projectName == "" {
			ctx.Write([]byte("no project"))
			return
		}
		prvCa := catchdict[projectName]
		pukCa := catchdictPuk[projectName]

		//解码
		DeAppid, err := PrivateDecode(Msg.Appid, prvCa)
		if err != nil {
			fmt.Println(err)
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		//
		if APPIDdict[projectName] != string(DeAppid) {
			ctx.Write([]byte("no APPID"))
			return
		}
		DeToken, err := PrivateDecode(Msg.Token, prvCa)
		if err != nil {
			fmt.Println(err)
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		_, found := Tokencatch.Get(string(DeToken)) //防止重放攻击
		if found {
			ctx.Write([]byte("re at"))
			return
		}
		DeTime, err := PrivateDecode(Msg.Time, prvCa)
		if err != nil {
			fmt.Println(err)
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}

		DeAddress, err := PrivateDecode(Msg.Address, prvCa)
		if err != nil {
			fmt.Println(err)
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		BLockAddressType, err := PrivateDecode(Msg.ETHAddress, prvCa)
		if err != nil {
			fmt.Println(err)
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		DeData, err := PrivateDecodeLong(Msg.Data, pukCa, prvCa)
		if err != nil {
			fmt.Println(err)
			fmt.Println(err)
			ctx.Write([]byte(fmt.Sprint(err)))
			return
		}
		int64Time := int64(binary.BigEndian.Uint64(DeTime))
		now := time.Now().Unix()
		if now-int64Time < 60 || now-int64Time > -60 {
			// fmt.Println(1)
			//查询数据库
			var res interface{}
			var found bool = false
			var Dat string
			if string(BLockAddressType) == "cfx" {
				res, found = CFXDATACatch.Get(acc.SHA256_strReturnString(string(DeAddress)))
			} else {
				res, found = ETHDATACatch.Get(acc.SHA256_strReturnString(string(DeAddress)))
			}
			if !found {
				fmt.Println("NONE")
				ctx.WriteString("NONE")
				return
			}
			Dat = res.(string)
			buf, err := hex.DecodeString(Dat)
			if err != nil {
				fmt.Println(err)
				ctx.Write([]byte(fmt.Sprintln(err)))
				return
			}
			debuf, err := ECCDecrypt(buf, *prk22)
			if err != nil {
				fmt.Println(err)
				ctx.Write([]byte(fmt.Sprint(err)))
				return
			}
			//RSA加密返回
			endebuf := publicEncode(debuf, DeData)
			ctx.Write(endebuf)
			app.Logger().Info("GetHalfPrvData")
		} else {
			ctx.Write([]byte("time or appid err"))
			return
		}
		// wg.Done()
		//加入已使用的token 防止重放
		Tokencatch.Set(string(DeToken), true, cache.DefaultExpiration)
		return

		// ctx.JSON(Msg)返回json
		// ctx.Write([]byte("SHPDS"))
	}
	//数据库获得 data
	//解密 data
	//puk 加密 data
	//传输数据
}

// /////////////////////////////////////AEC////////////////////////////////////
// AEC加密和解密（CRT模式）
func AEC_CRT_Crypt(text []byte, key []byte) []byte {
	//指定加密、解密算法为AES，返回一个AES的Block接口对象
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	//指定计数器,长度必须等于block的块尺寸
	count := []byte("1234567")
	//指定分组模式
	blockMode := cipher.NewCTR(block, count)
	//执行加密、解密操作
	message := make([]byte, len(text))
	blockMode.XORKeyStream(message, text)
	//返回明文或密文
	return message
}

// 使用rsa公钥加密文件
func publicEncode(plainText []byte, data []byte) []byte {
	//1. 读取公钥信息 放到data变量中
	//2. 将得到的字符串pem解码
	//1. 读取公钥信息 放到data变量中

	//2. 将得到的字符串pem解码
	block, _ := pem.Decode(data)
	//3. 使用x509将编码之后的公钥解析出来
	pubInterface, err2 := x509.ParsePKIXPublicKey(block.Bytes)
	if err2 != nil {
		panic(err2)
	}
	pubKey := pubInterface.(*rsa.PublicKey)

	//4. 使用公钥加密
	cipherText, err3 := rsa.EncryptPKCS1v15(rand.Reader, pubKey, plainText)
	if err3 != nil {
		panic(err3)
	}
	return cipherText
}

// 使用rsa公钥加密文件
func publicEncodeLong(plainText []byte, filename string) ([]byte, error) {

	//1. 读取公钥信息 放到data变量中
	file, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	stat, _ := file.Stat() //得到文件属性信息
	data := make([]byte, stat.Size())
	file.Read(data)
	file.Close()
	//2. 将得到的字符串pem解码
	block, _ := pem.Decode(data)

	//3. 使用x509将编码之后的公钥解析出来
	pubInterface, err2 := x509.ParsePKIXPublicKey(block.Bytes)
	if err2 != nil {
		panic(err2)
	}
	pubKey := pubInterface.(*rsa.PublicKey)
	partLen := pubKey.N.BitLen()/8 - 11
	chunks := split(plainText, partLen)
	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		bytes, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, chunk)
		if err != nil {
			return nil, err
		}
		buffer.Write(bytes)
	}
	return buffer.Bytes(), nil

}

// 使用rsa私钥解密
func PrivateDecode(cipherText []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	//1. 打开并读取私钥文件

	//4. 使用私钥将数据解密
	plainText, err4 := rsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherText)
	if err4 != nil {
		return nil, err4
	}
	return plainText, nil
}
func PrivateDecodeLong(cipherText []byte, pubKey *rsa.PublicKey, privateKey *rsa.PrivateKey) ([]byte, error) {
	partLen := pubKey.N.BitLen() / 8
	chunks := split(cipherText, partLen)
	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, chunk)
		if err != nil {
			return nil, err
		}
		buffer.Write(decrypted)
	}
	return buffer.Bytes(), nil
}

// //////////////////////////////////////区块链////////////////////////////////////
func GetCurrentDir() string { //获取当前目录路径
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatal(err)
	}
	return strings.Replace(dir, "\\", "/", -1)
}
func GetCurrentDir_Dbug() string { //获取当前目录路径
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("get current file path error")
	}
	currentDir := path.Join(filename, "../")
	return currentDir
}

func split(buf []byte, lim int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf[:])
	}
	return chunks
}

func ECCEncrypt(pt []byte, puk ecies.PublicKey) ([]byte, error) {
	ct, err := ecies.Encrypt(rand.Reader, &puk, pt, nil, nil)
	return ct, err
}

func ECCDecrypt(ct []byte, prk ecies.PrivateKey) ([]byte, error) {
	pt, err := prk.Decrypt(ct, nil, nil)
	return pt, err
}
func getKey() (*ecdsa.PrivateKey, error) {
	prk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return prk, err
	}
	return prk, nil
}

////////////////////////////////////////////////跨域/////////////////////////////////////

// 方法一
func CorsALL(ctx iris.Context) {
	ctx.Header("Access-Control-Allow-Origin", "*")
	if ctx.Request().Method == "OPTIONS" {
		ctx.Header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,PATCH,OPTIONS")
		ctx.Header("Access-Control-Allow-Headers", "Content-Type, Accept, Authorization")
		ctx.StatusCode(204)
		return
	}
	ctx.Next()
}

// 方法二
func CorsURL(ctx iris.Context, url string) {
	ctx.Header("Access-Control-Allow-Origin", url) //url:"http://localhost:17000"
	ctx.Header("Access-Control-Allow-Credentials", "true")
	ctx.Next()
}
