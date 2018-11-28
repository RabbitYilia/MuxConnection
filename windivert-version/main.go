package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/clmul/go-windivert"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Packet struct {
	Addr windivert.Address
	Data []byte
}

type ProtocolPacket struct {
	PacketTimestamp int64
	PacketData      map[int]string
	PacketCount     int
	PacketTotal     int
	Finish          bool
}

var (
	IPv4SrcMap   = make(map[int]string)
	IPv4DstMap   = make(map[int]string)
	IPv6SrcMap   = make(map[int]string)
	IPv6DstMap   = make(map[int]string)
	rxChannel    = make(chan Packet)
	txChannel    = make(chan Packet)
	md5Ctx       = md5.New()
	PacketBuffer = make(map[string]*ProtocolPacket)
	Handle       windivert.Handle
)

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	//Add rxAddr
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Fatal(err)
	}
	_, localnet192, err := net.ParseCIDR("192.168.0.0/16")
	_, localnet172, err := net.ParseCIDR("172.16.0.0/12")
	_, localnet169, err := net.ParseCIDR("169.254.0.0/16")
	_, localnet10, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		log.Fatal(err)
	}
	for _, address := range addrs {
		thisaddr := net.ParseIP(strings.Split(address.String(), "/")[0])
		if thisaddr.IsLoopback() || !thisaddr.IsGlobalUnicast() || thisaddr.IsUnspecified() {
			continue
		}
		if localnet10.Contains(thisaddr) || localnet169.Contains(thisaddr) || localnet172.Contains(thisaddr) || localnet192.Contains(thisaddr) {
			continue
		}
		if strings.Contains(thisaddr.String(), ".") {
			IPv4SrcMap[len(IPv4SrcMap)] = thisaddr.String()
		} else {
			IPv6SrcMap[len(IPv6SrcMap)] = thisaddr.String()
		}
		log.Println("Listen on:", thisaddr.String())
	}

	//listen
	Handle, err = windivert.Open("ipv6 or ( ip.Protocol!=2 and ip.DstAddr<3758096384)", 0, 0, 1)
	if err != nil {
		log.Fatal(err)
	}

	go RXLoop()
	go TXLoop()
	go ProcessLoop()
	go CleanBuffer()

	//Get DstIP
	HaveFile, err := PathExists("./dst.txt")
	if HaveFile {
		fi, err := os.Open("./dst.txt")
		if err != nil {
			log.Fatal(err)
		}
		defer fi.Close()
		br := bufio.NewReader(fi)
		for {
			a, _, c := br.ReadLine()
			if c == io.EOF {
				break
			}
			thisIP := net.ParseIP(string(a))
			if thisIP == nil {
				continue
			}
			if strings.Contains(string(a), ".") {
				IPv4DstMap[len(IPv4DstMap)] = thisIP.String()
			} else {
				IPv6DstMap[len(IPv6DstMap)] = thisIP.String()
			}
			log.Println("Send to:", string(a))
		}
	} else {
		for {
			input := GetInput("Dst IP")
			thisIP := net.ParseIP(input)
			if input == "" || thisIP == nil {
				break
			}
			if strings.Contains(input, ".") {
				IPv4DstMap[len(IPv4DstMap)] = thisIP.String()
			} else {
				IPv6DstMap[len(IPv6DstMap)] = thisIP.String()
			}
		}
	}
	if len(IPv4SrcMap) == 0 && len(IPv6SrcMap) == 0 {
		log.Fatal("No Address to listen")
	}
	if len(IPv4DstMap) == 0 && len(IPv6DstMap) == 0 {
		log.Fatal("No Address to send")
	}
	if len(IPv4SrcMap) == 0 && len(IPv4DstMap) == 0 {
		if len(IPv6SrcMap) == 0 || len(IPv6DstMap) == 0 {
			log.Fatal("Network Unreachable")
		}
	}
	if len(IPv6SrcMap) == 0 && len(IPv6DstMap) == 0 {
		if len(IPv4SrcMap) == 0 || len(IPv4DstMap) == 0 {
			log.Fatal("Network Unreachable")
		}
	}

	Send()
	Handle.Close()
}

func Send() {
	var DstIP net.IP
	var SrcIP net.IP
	var SrcPort int
	var DstPort int
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{}
	for {
		err := buffer.Clear()
		if err != nil {
			log.Fatal(err)
		}

		input := GetInput("Msg")
		if input == "" {
			break
		}
		Timestamp := strconv.FormatInt(time.Now().UnixNano(), 10)
		md5Ctx.Write([]byte(input + strconv.Itoa(RandInt(0, 65535))))
		MD5Sum := hex.EncodeToString(md5Ctx.Sum(nil))
		md5Ctx.Reset()
		SplitedMsgs := make(map[string]string)
		piece := 0
		for {
			piece += 1
			if len(input) < 10 {
				SplitedMsgs[strconv.Itoa(piece)] = input
				break
			}
			thislen := RandInt(1, len(input))
			SplitedMsgs[strconv.Itoa(piece)] = input[:thislen]
			input = input[thislen:]
		}

		for thispiece, piecedmsg := range SplitedMsgs {
			SrcPort = RandInt(1, 65535)
			DstPort = RandInt(1, 65535)
			switch RandInt(0, 1) {
			case 0:
				if len(IPv6SrcMap) != 0 && len(IPv6DstMap) != 0 {
					DstIP = net.ParseIP(IPv6DstMap[RandInt(0, len(IPv6DstMap)-1)])
					SrcIP = net.ParseIP(IPv6SrcMap[RandInt(0, len(IPv6SrcMap)-1)])
				} else {
					DstIP = net.ParseIP(IPv4DstMap[RandInt(0, len(IPv4DstMap)-1)])
					SrcIP = net.ParseIP(IPv4SrcMap[RandInt(0, len(IPv4SrcMap)-1)])
				}
			case 1:
				if len(IPv4SrcMap) != 0 && len(IPv4DstMap) != 0 {
					DstIP = net.ParseIP(IPv4DstMap[RandInt(0, len(IPv4DstMap)-1)])
					SrcIP = net.ParseIP(IPv4SrcMap[RandInt(0, len(IPv4SrcMap)-1)])
				} else {
					DstIP = net.ParseIP(IPv6DstMap[RandInt(0, len(IPv6DstMap)-1)])
					SrcIP = net.ParseIP(IPv6SrcMap[RandInt(0, len(IPv6SrcMap)-1)])
				}
			}

			TXData := make(map[string]string)
			TXData["Piece"] = strconv.Itoa(piece)
			TXData["ThisPiece"] = thispiece
			TXData["SrcIP"] = SrcIP.String()
			TXData["DstIP"] = DstIP.String()
			TXData["Timestamp"] = Timestamp
			TXData["MD5sum"] = MD5Sum
			TXData["PiecedMsg"] = piecedmsg
			TXJson, err := json.Marshal(TXData)
			if err != nil {
				log.Fatal(err)
			}

			UDPLayer := &layers.UDP{
				SrcPort: layers.UDPPort(SrcPort),
				DstPort: layers.UDPPort(DstPort),
				Length:  uint16(len(TXJson) + 8),
			}

			if strings.Contains(DstIP.String(), ",") {
				ipv4Layer := &layers.IPv4{
					SrcIP:    SrcIP,
					DstIP:    DstIP,
					Version:  uint8(4),
					TTL:      uint8(64),
					IHL:      uint8(5),
					Checksum: uint16(0),
					Protocol: layers.IPProtocolUDP,
					Length:   uint16(UDPLayer.Length + 20),
				}
				v4buffer := gopacket.NewSerializeBuffer()
				ipv4Layer.SerializeTo(v4buffer, options)
				v4package := v4buffer.Bytes()
				ipv4Layer.Checksum = checkSum(v4package[:20])

				FakeHeader := makeUDPFakeHeader(SrcIP, DstIP, ipv4Layer.Length, SrcPort, DstPort, UDPLayer.Length)
				FakeHeaderbyte, err := hex.DecodeString(FakeHeader)
				if err != nil {
					log.Fatal(err)
				}
				UDPLayer.Checksum = checkSum(FakeHeaderbyte)
				gopacket.SerializeLayers(buffer, options, ipv4Layer, UDPLayer)
			} else {
				ipv6Layer := &layers.IPv6{
					SrcIP:      SrcIP,
					DstIP:      DstIP,
					Version:    uint8(6),
					HopLimit:   uint8(64),
					Length:     uint16(UDPLayer.Length),
					NextHeader: layers.IPProtocolUDP,
				}
				FakeHeader := makeUDPFakeHeader(SrcIP, DstIP, ipv6Layer.Length, SrcPort, DstPort, UDPLayer.Length)
				FakeHeaderbyte, err := hex.DecodeString(FakeHeader)
				if err != nil {
					log.Fatal(err)
				}
				UDPLayer.Checksum = checkSum(FakeHeaderbyte)
				gopacket.SerializeLayers(buffer, options, ipv6Layer, UDPLayer)
			}
			TXPacket := Packet{
				Addr: windivert.Address{Direction: 0, IfIdx: 0, SubIfIdx: 0},
				Data: windivert.CalcChecksums(append(buffer.Bytes(), TXJson...)),
			}
			txChannel <- TXPacket
		}
	}
}

func ProcessLoop() {
	for {
		RXPacket := <-rxChannel
		IPVersion := int(RXPacket.Data[0]) >> 4
		var ThisRXPacket gopacket.Packet
		switch IPVersion {
		case 4:
			ThisRXPacket = gopacket.NewPacket(RXPacket.Data, layers.LayerTypeIPv4, gopacket.Lazy)
		case 6:
			ThisRXPacket = gopacket.NewPacket(RXPacket.Data, layers.LayerTypeIPv6, gopacket.Lazy)
		default:
			txChannel <- RXPacket
			continue
		}

		if ThisRXPacket.ApplicationLayer() != nil {
			RXdata := make(map[string]string)
			err := json.Unmarshal(ThisRXPacket.ApplicationLayer().Payload(), &RXdata)
			if err == nil {
				ProcessRXData(RXdata)
				continue
			}
		}
		txChannel <- RXPacket
	}
}

func ProcessRXData(RXData map[string]string) {
	MD5Sum := RXData["MD5sum"]
	ThisPieceStr := RXData["ThisPiece"]
	log.Println("[" + MD5Sum + "]" + "[" + ThisPieceStr + "/" + RXData["Piece"] + "]" + "From " + RXData["SrcIP"] + " to " + RXData["DstIP"] + " :")
	RXPacket, ok := PacketBuffer[MD5Sum]
	ThisPiece, err := strconv.Atoi(ThisPieceStr)
	if err != nil {
		return
	}
	if !ok {
		Timestamp, err := strconv.ParseInt(RXData["Timestamp"], 10, 64)
		if err != nil {
			log.Fatal(err)
		}
		Piece, err := strconv.Atoi(RXData["Piece"])
		if err != nil {
			return
		}
		PacketBuffer[MD5Sum] = &ProtocolPacket{Finish: false, PacketCount: 1, PacketTimestamp: Timestamp, PacketTotal: Piece, PacketData: make(map[int]string)}
		PacketBuffer[MD5Sum].PacketData[ThisPiece] = RXData["PiecedMsg"]
		if PacketBuffer[MD5Sum].PacketCount == PacketBuffer[MD5Sum].PacketTotal {
			DataStr := ""
			PacketBuffer[MD5Sum].Finish = true
			for i := 1; i <= PacketBuffer[MD5Sum].PacketTotal; i++ {
				DataStr += PacketBuffer[MD5Sum].PacketData[i]
			}
			log.Println(string(DataStr))
			delete(PacketBuffer, MD5Sum)
		}
	} else {
		if RXPacket.PacketData[ThisPiece] != RXData["PiecedMsg"] {
			RXPacket.PacketData[ThisPiece] = RXData["PiecedMsg"]
			RXPacket.PacketCount += 1
		}
		if RXPacket.PacketCount == RXPacket.PacketTotal {
			DataStr := ""
			RXPacket.Finish = true
			for i := 1; i <= RXPacket.PacketTotal; i++ {
				DataStr += RXPacket.PacketData[i]
			}
			log.Println(string(DataStr))
			delete(PacketBuffer, MD5Sum)
		}
	}
}

func RXLoop() {
	for {
		RXBuffer := make([]byte, 65535)
		RXPacketLen, RXAddr, err := Handle.Recv(RXBuffer)
		RXBuffer = RXBuffer[:RXPacketLen]
		if err != nil {
			log.Fatal(err)
		}
		rxChannel <- Packet{Addr: RXAddr, Data: RXBuffer}
	}
}

func TXLoop() {
	for {
		TXPacket := <-txChannel
		_, err := Handle.Send(TXPacket.Data, TXPacket.Addr)
		if err != nil {
			continue
			//log.Fatal(err)
		}
	}
}

func GetInput(tip string) string {
	for {
		log.Println("Please input " + tip + ":")
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
		return input
	}
	return ""
}

func RandInt(min, max int) int {
	rand.Seed(time.Now().UnixNano() * rand.Int63n(100))
	return min + rand.Intn(max-min+1)
}

func CleanBuffer() {
	for {
		time.Sleep(60 * time.Second)
		TimeOutTime := time.Now().UnixNano() + 60*time.Second.Nanoseconds()
		for MD5Sum, Pack := range PacketBuffer {
			if Pack.PacketTimestamp < TimeOutTime {
				delete(PacketBuffer, MD5Sum)
			}
		}
	}
}

func makeUDPFakeHeader(SrcIPv6 net.IP, DstIPv6 net.IP, iplen uint16, SrcPort int, DstPort int, udplen uint16) string {
	UDPFakeHeader := ""
	FakeUDPSrc, err := SrcIPv6.MarshalText()
	if err != nil {
		log.Fatal(err)
	}
	FakeUDPDst, err := DstIPv6.MarshalText()
	if err != nil {
		log.Fatal(err)
	}
	var convbuffer bytes.Buffer
	err = binary.Write(&convbuffer, binary.BigEndian, uint8(0))
	if err != nil {
		log.Fatal(err)
	}
	UDPFakeHeader += hex.EncodeToString(FakeUDPSrc)
	UDPFakeHeader += hex.EncodeToString(FakeUDPDst)
	UDPFakeHeader += hex.EncodeToString(convbuffer.Bytes())
	convbuffer.Reset()
	err = binary.Write(&convbuffer, binary.LittleEndian, uint8(17))
	if err != nil {
		log.Fatal(err)
	}
	UDPFakeHeader += hex.EncodeToString(convbuffer.Bytes())
	convbuffer.Reset()
	err = binary.Write(&convbuffer, binary.LittleEndian, iplen)
	if err != nil {
		log.Fatal(err)
	}
	UDPFakeHeader += hex.EncodeToString(convbuffer.Bytes())
	convbuffer.Reset()
	err = binary.Write(&convbuffer, binary.LittleEndian, uint16(SrcPort))
	if err != nil {
		log.Fatal(err)
	}
	UDPFakeHeader += hex.EncodeToString(convbuffer.Bytes())
	convbuffer.Reset()
	err = binary.Write(&convbuffer, binary.LittleEndian, uint16(DstPort))
	if err != nil {
		log.Fatal(err)
	}
	UDPFakeHeader += hex.EncodeToString(convbuffer.Bytes())
	convbuffer.Reset()
	err = binary.Write(&convbuffer, binary.LittleEndian, udplen)
	if err != nil {
		log.Fatal(err)
	}
	UDPFakeHeader += hex.EncodeToString(convbuffer.Bytes())
	convbuffer.Reset()
	err = binary.Write(&convbuffer, binary.LittleEndian, uint16(0))
	if err != nil {
		log.Fatal(err)
	}
	UDPFakeHeader += hex.EncodeToString(convbuffer.Bytes())
	convbuffer.Reset()
	return UDPFakeHeader
}

func checkSum(msg []byte) uint16 {
	sum := 0
	for n := 1; n < len(msg)-1; n += 2 {
		sum += int(msg[n])*256 + int(msg[n+1])
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += (sum >> 16)
	var ans = uint16(^sum)
	return ans
}

func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}
