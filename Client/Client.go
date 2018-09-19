package main

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {

	conn, err := net.Dial("tcp", "127.0.0.1:6161")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	writer := bufio.NewWriter(conn)
	//reader := bufio.NewReader(conn)

	md5Ctx := md5.New()
	for {
		timestamp := strconv.FormatInt(time.Now().UnixNano(), 10)
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
		msg := hex.EncodeToString([]byte(input))
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
}

func RandInt(min, max int) int {
	rand.Seed(time.Now().UnixNano() * rand.Int63n(100))
	return min + rand.Intn(max-min+1)
}
