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
	"os"
	"strconv"
	"strings"
	"time"
)

var md5Ctx hash.Hash
var packetbuffer map[string][]string
var packettimestamp map[string]string
var packetcount map[string]int
var packettotal map[string]int

func main() {
	md5Ctx = md5.New()
	packetbuffer = make(map[string][]string)
	packettimestamp = make(map[string]string)
	packetcount = make(map[string]int)
	packettotal = make(map[string]int)

	conn, err := net.Dial("tcp", "127.0.0.1:6161")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	writer := bufio.NewWriter(conn)
	//reader := bufio.NewReader(conn)

	for {
		log.Println("Please input msg:")
		inputReader := bufio.NewReader(os.Stdin)
		input, err := inputReader.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}
		input = strings.Trim(input, "\n")
		input = strings.Trim(input, "\r")
		if input == "" {
			break
		}
		ProcessTXByte([]byte(input), writer)
	}
}

func RandInt(min, max int) int {
	rand.Seed(time.Now().UnixNano() * rand.Int63n(100))
	return min + rand.Intn(max-min+1)
}

func ProcessTXByte(TXByte []byte, writer *bufio.Writer) {
	timestamp := strconv.FormatInt(time.Now().UnixNano(), 10)
	msg := hex.EncodeToString(TXByte)
	md5Ctx.Write([]byte(msg))
	md5sum := hex.EncodeToString(md5Ctx.Sum(nil))
	md5Ctx.Reset()
	splitedmsgs := make(map[string]string)
	piece := 0
	log.Println(msg)
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
		log.Println("OK")
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
