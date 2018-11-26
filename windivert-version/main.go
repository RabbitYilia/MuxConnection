// PacketMaker project main.go
package main

import (
	"C"
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/binary"
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

	"github.com/clmul/go-windivert"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var IPv6Map []net.IP
var IPv4Map []net.IP
var md5Ctx hash.Hash

var PacketBuffer map[string][]string
var PacketTimestamp map[string]string
var PacketCount map[string]int
var PacketTotal map[string]int

func main() {
	md5Ctx = md5.New()

	PacketBuffer = make(map[string][]string)
	PacketTimestamp = make(map[string]string)
	PacketCount = make(map[string]int)
	PacketTotal = make(map[string]int)

	Handle, err := windivert.Open("true", 0, 0, 0)
	if err != nil {
		log.Fatal(err)
	}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Fatal(err)
	}
	_, localnet192, err := net.ParseCIDR("192.168.0.0/16")
	_, localnet172, err := net.ParseCIDR("172.16.0.0/12")
	_, localnet10, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		log.Fatal(err)
	}

	for _, address := range addrs {
		thisaddr := address.(*net.IPNet)
		if thisaddr.IP.IsLoopback() || !thisaddr.IP.IsGlobalUnicast() || thisaddr.IP.IsUnspecified() {
			continue
		}
		if localnet10.Contains(thisaddr.IP) || localnet172.Contains(thisaddr.IP) || localnet192.Contains(thisaddr.IP) {
			continue
		}
		if strings.Contains(strings.Split(thisaddr.String(), "/")[0], ".") {
			IPv4Map = append(IPv4Map, thisaddr.IP)
		} else {
			IPv6Map = append(IPv6Map, thisaddr.IP)
		}

		log.Println("Listen on:", strings.Split(thisaddr.String(), "/")[0])
	}
	if len(IPv4Map) == 0 && len(IPv6Map) == 0 {
		log.Fatal("No Address to listen")
	}
	go RXLoop(Handle)
	TXLoop(Handle)
	Handle.Close()
}

func TXLoop(Handle windivert.Handle) {
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{}
	input := GetInput("Dst IP")
	DstIP := net.ParseIP(input)
	if strings.Contains(DstIP.String(), ".") && len(IPv4Map) == 0 {
		log.Fatal("Cannot send to this v4 addr")
	}
	if strings.Contains(DstIP.String(), ":") && len(IPv6Map) == 0 {
		log.Fatal("Cannot send to this v6 addr")
	}
	if DstIP == nil {
		log.Fatal("Invaild Addr")
	}
	for {
		SrcPort := RandInt(1, 65535)
		DstPort := RandInt(1, 65535)
		err := buffer.Clear()
		if err != nil {
			log.Fatal(err)
		}

		TXAddr := windivert.Address{}
		TXAddr.Direction = 0
		TXAddr.IfIdx = 0
		TXAddr.SubIfIdx = 0

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

		Timestamp := strconv.FormatInt(time.Now().UnixNano(), 10)
		md5Ctx.Write([]byte(input))
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
			TXData := make(map[string]string)
			TXData["Piece"] = strconv.Itoa(piece)
			TXData["thisPiece"] = thispiece
			TXData["timestamp"] = Timestamp
			TXData["md5sum"] = MD5Sum
			TXData["piecedmsg"] = piecedmsg
			TXJson, err := json.Marshal(TXData)
			if err != nil {
				log.Fatal(err)
			}

			UDPLayer := &layers.UDP{}
			UDPLayer.SrcPort = layers.UDPPort(SrcPort)
			UDPLayer.DstPort = layers.UDPPort(DstPort)
			UDPLayer.Length = uint16(len(TXJson) + 8)

			var SrcIP net.IP
			if strings.Contains(DstIP.String(), ",") {
				SrcIP = IPv4Map[RandInt(0, len(IPv4Map)-1)]

				ipv4Layer := &layers.IPv4{}
				ipv4Layer.SrcIP = SrcIP
				ipv4Layer.DstIP = DstIP
				ipv4Layer.Version = uint8(4)
				ipv4Layer.TTL = uint8(64)
				ipv4Layer.Checksum = uint16(0)
				ipv4Layer.Protocol = layers.IPProtocolUDP
				ipv4Layer.IHL = uint8(5)
				ipv4Layer.Length = uint16(UDPLayer.Length + 20)
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
				SrcIP = IPv6Map[RandInt(0, len(IPv6Map)-1)]
				ipv6Layer := &layers.IPv6{}
				ipv6Layer.SrcIP = SrcIP
				ipv6Layer.DstIP = DstIP
				ipv6Layer.Version = uint8(6)
				ipv6Layer.HopLimit = uint8(64)
				ipv6Layer.Length = uint16(UDPLayer.Length)
				ipv6Layer.NextHeader = layers.IPProtocolUDP

				FakeHeader := makeUDPFakeHeader(SrcIP, DstIP, ipv6Layer.Length, SrcPort, DstPort, UDPLayer.Length)
				FakeHeaderbyte, err := hex.DecodeString(FakeHeader)
				if err != nil {
					log.Fatal(err)
				}
				UDPLayer.Checksum = checkSum(FakeHeaderbyte)
				gopacket.SerializeLayers(buffer, options, ipv6Layer, UDPLayer)
			}

			TXPacket := append(buffer.Bytes(), TXJson...)
			TXPacket = windivert.CalcChecksums(TXPacket)

			_, err = Handle.Send(TXPacket, TXAddr)
			if err != nil {
				log.Fatal(err)
			}
		}
	}
}

func RXLoop(Handle windivert.Handle) {
	for true {
		RXPacket := make([]byte, 65535)
		RXPacketLen, RXAddr, err := Handle.Recv(RXPacket)
		RXPacket = RXPacket[:RXPacketLen]
		if err != nil {
			log.Fatal(err)
		}
		go ProcessRX(Handle, RXPacket, RXAddr)
	}
}

func ProcessRX(Handle windivert.Handle, RXPacket []byte, RXAddr windivert.Address) {
	IPVersion := int(RXPacket[0] >> 4)
	var SrcIP, DstIP net.IP
	var SrcPort, DstPort string
	var ThisRXPacket gopacket.Packet
	switch IPVersion {
	case 4:
		ThisRXPacket = gopacket.NewPacket(RXPacket, layers.LayerTypeIPv4, gopacket.Lazy)
		IPv4Header, _ := ThisRXPacket.NetworkLayer().(*layers.IPv4)
		SrcIP = IPv4Header.SrcIP
		DstIP = IPv4Header.DstIP
	case 6:
		ThisRXPacket = gopacket.NewPacket(RXPacket, layers.LayerTypeIPv6, gopacket.Lazy)
		IPv6Header, _ := ThisRXPacket.NetworkLayer().(*layers.IPv6)
		SrcIP = IPv6Header.SrcIP
		DstIP = IPv6Header.DstIP
	default:
		_, err := Handle.Send(RXPacket, RXAddr)
		if err != nil {
			log.Fatal(err)
		}
	}
	if ThisRXPacket.TransportLayer() != nil {
		switch ThisRXPacket.TransportLayer().LayerType() {
		case layers.LayerTypeUDP:
			UDPHeader := ThisRXPacket.TransportLayer().(*layers.UDP)
			SrcPort = UDPHeader.SrcPort.String()
			DstPort = UDPHeader.DstPort.String()
		case layers.LayerTypeTCP:
			//Do not Process At Present
			_, err := Handle.Send(RXPacket, RXAddr)
			if err != nil {
				log.Fatal(err)
			}
			return

			TCPHeader := ThisRXPacket.TransportLayer().(*layers.TCP)
			SrcPort = TCPHeader.SrcPort.String()
			DstPort = TCPHeader.DstPort.String()
		default:
			_, err := Handle.Send(RXPacket, RXAddr)
			if err != nil {
				log.Fatal(err)
			}
		}
	}

	if ThisRXPacket.ApplicationLayer() != nil {
		RXdata := make(map[string]string)
		err := json.Unmarshal(ThisRXPacket.ApplicationLayer().Payload(), &RXdata)
		if err == nil {
			log.Println("From " + SrcIP.String() + "#" + SrcPort + " to " + DstIP.String() + "#" + DstPort + " :")
			ProcessRXData(RXdata)
			return
		}
	}
	_, err := Handle.Send(RXPacket, RXAddr)
	if err != nil {
		log.Fatal(err)
	}
}

func ProcessRXData(RXData map[string]string) {
	databuffer, ok := PacketBuffer[RXData["md5sum"]]
	if !ok {
		PacketTimestamp[RXData["md5sum"]] = RXData["timestamp"]
		thistotal, err := strconv.Atoi(RXData["Piece"])
		if err != nil {
			return
		}
		packetint, err := strconv.Atoi(RXData["thisPiece"])
		if err != nil {
			return
		}

		var thisbuffer []string
		thisbuffer = make([]string, thistotal+1)
		PacketBuffer[RXData["md5sum"]] = thisbuffer
		PacketCount[RXData["md5sum"]] = 1
		PacketTotal[RXData["md5sum"]] = thistotal
		PacketBuffer[RXData["md5sum"]][packetint] = RXData["piecedmsg"]
		if PacketCount[RXData["md5sum"]] == PacketTotal[RXData["md5sum"]] {
			DataStr := ""
			for i := 1; i <= PacketTotal[RXData["md5sum"]]; i++ {
				DataStr += PacketBuffer[RXData["md5sum"]][i]
			}
			log.Println(string(DataStr))
			delete(PacketBuffer, RXData["md5sum"])
			delete(PacketTimestamp, RXData["md5sum"])
			delete(PacketCount, RXData["md5sum"])
			delete(PacketTotal, RXData["md5sum"])
		}
	} else {
		packetint, err := strconv.Atoi(RXData["thisPiece"])
		if err != nil {
			return
		}
		if databuffer[packetint] != RXData["piecedmsg"] {
			databuffer[packetint] = RXData["piecedmsg"]
			PacketCount[RXData["md5sum"]] += 1
		}
		if PacketCount[RXData["md5sum"]] == PacketTotal[RXData["md5sum"]] {
			DataStr := ""
			for i := 1; i <= PacketTotal[RXData["md5sum"]]; i++ {
				DataStr += PacketBuffer[RXData["md5sum"]][i]
			}
			log.Println(string(DataStr))
			delete(PacketBuffer, RXData["md5sum"])
			delete(PacketTimestamp, RXData["md5sum"])
			delete(PacketCount, RXData["md5sum"])
			delete(PacketTotal, RXData["md5sum"])
		}
	}
}

func RandInt(min, max int) int {
	rand.Seed(time.Now().UnixNano() * rand.Int63n(100))
	return min + rand.Intn(max-min+1)
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

func CleanBuffer() {
	for {
		TimeOutTime := time.Now().UnixNano() + 10*time.Second.Nanoseconds()
		for MD5Sum, TimestampStr := range PacketTimestamp {
			Timestamp, err := strconv.ParseInt(TimestampStr, 10, 64)
			if err != nil {
				log.Fatal(err)
				delete(PacketTimestamp, MD5Sum)
				delete(PacketCount, MD5Sum)
			}
			if Timestamp < TimeOutTime {
				delete(PacketTimestamp, MD5Sum)
				delete(PacketCount, MD5Sum)
			}
		}
		time.Sleep(10 * time.Second)
	}
}
