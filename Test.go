package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"unsafe"
	"log"
	"time"
	"net"
)

//CGO_ENABLED=0 GOOS=linux GOARCH=386 go build

const URL_PREFIX string = "http://192.168.17.1:16621/"
var CHECK_LOG_ROOT string = ""
var DebugLog *log.Logger = nil

// var InterfaceUrls = [...]string{"", ""}
var urlMap map[string][]string = make(map[string][]string)

var apiActions = []string{"lasthb", "getmac", "getinfo", "hit", "userauth", "user", "^pagetime", "^httplog", "^checklog", "^errorlog", "^report", "^log", "^login", "user4wifi", "location"}
var opActions = []string{"selfcheck", "basiccheck", "packageinfo", "proxy", "debugmode", "usbupdateprocess", "usbupdateresult"}
var omActions = []string{"netex", "server", "flowcheck"}

//请求参数
var urlParams map[string][]string = make(map[string][]string)

//其他需要检测的接口
var otherUrls = []string{"", "", ""}

//需要检测的文件路径
var fileRoots = []string{
	"/mnt/disk/airmedia/wfportal",
	"/mnt/disk/wangfan",
	"/mnt/storage/yuqi/nginx/sbin/nginx",
	"/mnt/storage/yuqi/nginx/logs/error.log",
	"/mnt/storage/yuqi/nginx/conf/nging.conf",
	"/etc/white_list.conf",
	"/etc/dns.blacklist"}

//需要调用检查的命令
var commandCheck = []string{
	"ps -ef|grep hb",
	"curl -d '{\"mac\":\"58:44:98:b8:6f:6b\",\"pass\":1,\"traffic\":81920}' http://www.wangfanwifi.com:1958/control",
	"stbget wifi",
	"stbget gps"}
var commandSendCount int = 0;
const commandUrl = URL_PREFIX + "op/proxy?name=CMD"

type CMD struct {
	Id   string
	Cmd0 string
	Cmd1 string
	Cmd2 string
}

//初始化函数
func init() {
	urlMap["api"] = apiActions
	urlMap["op"] = opActions
	urlMap["om"] = omActions
	urlMap["onWifi"] = []string{""}
	urlMap["offWifi"] = []string{""}
	urlMap["offInternet"] = []string{""}

	//初始化请求参数
	urlParams["getinfo"] = []string{"", "?name=s_m", "?name=extends", "?name=s_m_iccid"}
	urlParams["hit"] = []string{"/info", "/data/5"}
	urlParams["userauth"] = []string{"?uid=63a189f34fc3423a8031a3d896b957bb&limit=10240&product=portal&register_type=wechat&version=T_2.5.3"}
	urlParams["userinfo"] = []string{"/flow", "/connectTime", "/logcount", "/active"}
	urlParams["packageinfo"] = []string{"?name=gpsv1", "?name=gpsv2", "?name=D1", "?name=basic", "?name=realtime", "?name=disconnectAt", "?name=userflowlist"}

	//初始化log
	currentPath,err := os.Getwd();
	if err != nil {
		log.Fatalln("get project root fail!")
	}
	file,err := os.Create( currentPath + "/" + "runtime.log")
	if err != nil {
		log.Fatalln("create file fail!")
	}
	DebugLog = log.New(file, time.Now().String() + " [Debug]",log.Llongfile)
	if DebugLog == nil {
		log.Fatalln("init logger error!")
	}
	//初始化日志文件路径
	CHECK_LOG_ROOT = currentPath + "/" + "go_check.log"
}

//调用接口并且返回结果
func checkInterface(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "interface error:" + url, err
	}
	defer resp.Body.Close()
	body, readErr := ioutil.ReadAll(resp.Body)
	if readErr != nil {
		return "interface error:" + url, readErr
	}
	return string(body), nil
}

func postCommand(cmd CMD) (string, error) {
	jsonBytes, err := json.Marshal(cmd)
	if err != nil {
		panic(err)
	}
	resp, err := http.Post(commandUrl, "application/json", strings.NewReader(strings.ToLower(string(jsonBytes[:]))))
	if err != nil {
		return "command error", err
	}
	defer resp.Body.Close()
	body, readErr := ioutil.ReadAll(resp.Body)
	if readErr != nil {
		return "command error", readErr
	}
	return string(body), nil
}

//调用所有接口并记录log
func checkAllInterface() {
	if _, err := os.Stat(CHECK_LOG_ROOT); os.IsExist(err) {
		os.Remove(CHECK_LOG_ROOT)

	} else {
		os.Create(CHECK_LOG_ROOT)
	}
	file, err2 := os.OpenFile(CHECK_LOG_ROOT, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0x644)
	if err2 != nil {
		DebugLog.Println(err2.Error())
	}
	defer file.Close()
	for key := range urlMap {
		for _, action := range urlMap[key] {
			if strings.HasPrefix(action, "^") {
				continue
			}
			url := URL_PREFIX + key + "/" + action
			result, err := checkInterface(url)
			if err != nil {
				DebugLog.Println(err2.Error())
			}
			file.WriteString("\n调用接口: " + url + "\n" + result + "\n")
		}
	}
}

func checkFile() {
	for _, value := range fileRoots {
		_, err := os.Stat(value)
		fmt.Println("file " + value + " Exit:" + strconv.FormatBool(os.IsNotExist(err)))
	}
}

func downloadFile(url string, target string) {
	resp, err := http.Get(url)
	if err != nil {
		DebugLog.Println(err.Error())
		return
	}
	var temp = strings.Split(url, "/")
	var fileName = temp[len(temp)-1]
	if !strings.HasSuffix(target, "/") {
		target = target + "/"
	}

	file, err := os.Create(target + fileName)
	if err != nil {
		DebugLog.Println(err.Error())
		return
	}

	io.Copy(file, resp.Body)
}

//调用命令并且返回结果
//func checkCommendResult() {
//	for _, command := range commandCheck {
//		cmd := exec.Command("/bin/sh", "-c", command)
//		result, err := cmd.Output()
//
//		if err != nil {
//			DebugLog.Println(err2.Error())
//		}
//
//		fmt.Println(string(result[:]))
//
//	}
//}

func S2B(s *string) []byte {
	return *(*[]byte)(unsafe.Pointer((*reflect.SliceHeader)(unsafe.Pointer(s))))
}

var listenComplete chan int = make(chan int)
var requestCount int = 0;
func httpServer(){
	//起一个小型服务器,监听8708端口
	http.HandleFunc("/cmdresult", CmdResultHandler)
	err2 := http.ListenAndServe(":8708", nil)
	if err2 != nil {
		log.Fatal("ListenAndServe: ", err2)
	}

}

func CmdResultHandler(w http.ResponseWriter, req *http.Request) {

	result, err := ioutil.ReadAll(req.Body)
	if err != nil {
		DebugLog.Println(err.Error())
	}
	file, err2 := os.OpenFile(CHECK_LOG_ROOT, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0777)
	if err2 != nil {
		DebugLog.Println(err2.Error())
	}
	defer file.Close()
	file.WriteString(string(result[:]) + "\n")
	requestCount =requestCount + 1
	DebugLog.Println("REQUEST COUNT:" + strconv.Itoa(requestCount))
	if requestCount >= commandSendCount {
		listenComplete <- 0 //执行完毕
	}
	fmt.Fprintf(w, "hello I'm DMA!")
}

func checkTime(timestamp int64){
	for  {
		time.Sleep(time.Second) //sleep 1 秒
		if time.Now().Unix() - timestamp >= 5 * 60{
			count := time.Now().Unix() - timestamp
			DebugLog.Println(count)
			break
		}
	}
	DebugLog.Println("THREAD HAS RUN LANG OVER 5 MINIS! ")
	listenComplete <- 0
}
func getLocalIP() (string,error){
	addrs,err := net.InterfaceAddrs()
	if err != nil{
		return "",err
	}
	for _,temp := range addrs{
		if ip,ok := temp.(*net.IPNet);ok && !ip.IP.IsLoopback(){
			if ip.IP.To4() != nil && strings.HasPrefix(ip.IP.To4().String(),"192.168"){
				return ip.IP.String(),nil
			}
		}

	}
	return "",nil
}
//主函数
func main() {

	//检测所有接口
	checkAllInterface()
	//测试心跳版本下载
	//var url = "http://139.217.16.155/heartbeat/heartbeat.20170606.jar"
	//downloadFile(url, "/Users/jerry/home/")
	startTimeStamp := time.Now().Unix()
	go checkTime(startTimeStamp)
	go httpServer()
	time.Sleep(1 * time.Second )
	//测试命令发送和结果接收
	ip,ipErr := getLocalIP()
	if ipErr != nil {
		panic(ipErr)
	}
	if len(ip) == 0 {
		return
	}
	DebugLog.Println(ip)
	for index,_ := range commandCheck {
		if index%3 == 0 {
			commandSendCount++
			var cmd1 string = ""
			if index + 1 <= len(commandCheck) - 1 {
				cmd1 = commandCheck[index + 1]
				commandSendCount++
			}

			var cmd2 string = ""
			if index + 2 <= len(commandCheck) - 1 {
				commandSendCount++
				cmd1 = commandCheck[index + 2]
			}

			cmd := CMD{ip, commandCheck[index], cmd1, cmd2}
			_, err := postCommand(cmd)
			if err != nil {
				DebugLog.Println(err)
				return
			}
		}
	}

	DebugLog.Println("SEND COMMAND NUBMER:" + strconv.Itoa(commandSendCount))
	<-listenComplete
}


