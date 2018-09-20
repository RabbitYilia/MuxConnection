package main

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"hash"
	"log"
	"math/rand"
	"net"
	"strconv"
	"time"
)

var packetbuffer map[string][]string
var packettimestamp map[string]string
var packetcount map[string]int
var packettotal map[string]int
var md5Ctx hash.Hash

func main() {
	md5Ctx = md5.New()
	packetbuffer = make(map[string][]string)
	packettimestamp = make(map[string]string)
	packetcount = make(map[string]int)
	packettotal = make(map[string]int)
	server, err := net.Listen("tcp", "127.0.0.1:6161")
	if err != nil {
		log.Fatal(err)
	}
	defer server.Close()
	for {
		conn, err := server.Accept()
		if err != nil {
			log.Fatal(err)
		}
		handleRequest(conn)
	}
}

// 处理接收到的connection
//
func handleRequest(conn net.Conn) {
	// 构建reader和writer
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	for {
		RXByte, _, err := reader.ReadLine()
		if err != nil {
			return
		}
		ProcessRXByte(RXByte)
		ProcessTXByte([]byte("OK"), writer)
	}
}

func ProcessTXByte(TXByte []byte, writer *bufio.Writer) {
	timestamp := strconv.FormatInt(time.Now().UnixNano(), 10)
	msg := hex.EncodeToString(TXByte)
	md5Ctx.Write([]byte(msg))
	md5sum := hex.EncodeToString(md5Ctx.Sum(nil))
	md5Ctx.Reset()
	splitedmsgs := make(map[string]string)
	piece := 0
	for {
		piece += 1
		if len(msg) < 10 {
			splitedmsgs[strconv.Itoa(piece)] = msg
			break
		}
		thislen := RandInt(1, len(msg))
		splitedmsgs[strconv.Itoa(piece)] = msg[:thislen]
		msg = msg[thislen:]
	}
	for thispiece, piecedmsg := range splitedmsgs {
		var SendData = make(map[string]string)
		SendData["Piece"] = strconv.Itoa(piece)
		SendData["thisPiece"] = thispiece
		SendData["timestamp"] = timestamp
		SendData["md5sum"] = md5sum
		SendData["piecedmsg"] = piecedmsg
		SendJson, err := json.Marshal(SendData)
		if err != nil {
			log.Fatal(err)
		}
		writer.Write([]byte(SendJson))
		writer.Write([]byte("\n"))
		writer.Flush()
	}
}

func ProcessRXByte(RXByte []byte) {
	RXdata := make(map[string]string)
	err := json.Unmarshal(RXByte, &RXdata)
	if err != nil {
		return
	}
	databuffer, ok := packetbuffer[RXdata["md5sum"]]
	if !ok {
		packettimestamp[RXdata["md5sum"]] = RXdata["timestamp"]
		thistotal, err := strconv.Atoi(RXdata["Piece"])
		if err != nil {
			return
		}
		packetint, err := strconv.Atoi(RXdata["thisPiece"])
		if err != nil {
			return
		}

		var thisbuffer []string
		thisbuffer = make([]string, thistotal+1)
		packetbuffer[RXdata["md5sum"]] = thisbuffer
		packetcount[RXdata["md5sum"]] = 1
		packettotal[RXdata["md5sum"]] = thistotal
		packetbuffer[RXdata["md5sum"]][packetint] = RXdata["piecedmsg"]
		if packetcount[RXdata["md5sum"]] == packettotal[RXdata["md5sum"]] {
			DataStr := ""
			for i := 1; i <= packettotal[RXdata["md5sum"]]; i++ {
				DataStr += packetbuffer[RXdata["md5sum"]][i]
			}
			ByteData, err := hex.DecodeString(DataStr)
			if err != nil {
				return
			}
			log.Println(string(ByteData))
			delete(packetbuffer, RXdata["md5sum"])
			delete(packettimestamp, RXdata["md5sum"])
			delete(packetcount, RXdata["md5sum"])
			delete(packettotal, RXdata["md5sum"])
		}
	} else {
		packetint, err := strconv.Atoi(RXdata["thisPiece"])
		if err != nil {
			return
		}
		databuffer[packetint] = RXdata["piecedmsg"]
		packetcount[RXdata["md5sum"]] += 1
		if packetcount[RXdata["md5sum"]] == packettotal[RXdata["md5sum"]] {
			DataStr := ""
			for i := 1; i <= packettotal[RXdata["md5sum"]]; i++ {
				DataStr += packetbuffer[RXdata["md5sum"]][i]
			}
			ByteData, err := hex.DecodeString(DataStr)
			if err != nil {
				return
			}
			log.Println(string(ByteData))
			delete(packetbuffer, RXdata["md5sum"])
			delete(packettimestamp, RXdata["md5sum"])
			delete(packetcount, RXdata["md5sum"])
			delete(packettotal, RXdata["md5sum"])
		}
	}
}

func RandInt(min, max int) int {
	rand.Seed(time.Now().UnixNano() * rand.Int63n(100))
	return min + rand.Intn(max-min+1)
}
