package main

import (
	"bufio"
	"log"
	"net"
)

func main() {
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
		go handleRequest(conn)
	}
}

// 处理接收到的connection
//
func handleRequest(conn net.Conn) {
	// 构建reader和writer
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	for {
		b, _, err := reader.ReadLine()
		log.Println(b)
		if err != nil {
			return
		}
		writer.Write([]byte("\n"))
		writer.Flush()
	}
}
