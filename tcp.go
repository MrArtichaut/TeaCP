package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	FlagFIN = iota // 0 0000 0001
	FlagSYN        // 0 0000 0010
	FlagRST        // 0 0000 0100
	FlagPSH        // 0 0000 1000
	FlagACK        // 0 0001 0000
	FlagURG        // 0 0010 0000
	FlagECE        // 0 0100 0000
	FlagCWR        // 0 1000 0000
	FlagNS         // 1 0000 0000
)

//TCPPacket structure
type TCPPacket struct {
	SrcPort    uint16
	DestPort   uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8  // 4 bits
	Flags      uint16 // 3 bits (reserved) + 9 bits
	WindowSize uint16
	Checksum   uint16
	Urgent     uint16
	Options    []TCPOption
	Data       []byte
}

type TCPOption struct {
	Kind   uint8
	Length uint8
	Data   []byte
}

func NewTCPPacket(data []byte) *TCPPacket {
	var packet TCPPacket
	reader := bytes.NewReader(data)
	binary.Read(reader, binary.BigEndian, &packet.SrcPort)
	binary.Read(reader, binary.BigEndian, &packet.DestPort)
	binary.Read(reader, binary.BigEndian, &packet.SeqNum)
	binary.Read(reader, binary.BigEndian, &packet.AckNum)

	var field uint16
	binary.Read(reader, binary.BigEndian, &field)
	fmt.Printf("decode flags %x %08b %08b\n", field, uint8(field>>8), uint8(field))

	packet.DataOffset = uint8(field >> 12)
	packet.Flags = field & 0xfff

	binary.Read(reader, binary.BigEndian, &packet.WindowSize)
	binary.Read(reader, binary.BigEndian, &packet.Checksum)
	binary.Read(reader, binary.BigEndian, &packet.Urgent)

	if packet.DataOffset > 5 {

	}

	headerLen := packet.DataOffset * 4

	if len(data) > int(headerLen) {
		packet.Data = data[headerLen:]
	}

	return &packet
}

func (packet *TCPPacket) SetFlag(flag uint8) {
	packet.Flags |= (1 << flag)
}

func (packet *TCPPacket) ClearFlag(flag uint8) {
	packet.Flags &^= (1 << flag)
}

func (packet *TCPPacket) HasFlag(flag uint8) bool {
	return (packet.Flags>>flag)&0x1 != 0
}

func (packet *TCPPacket) Marshall(srcIP, dstIP string) []byte {
	packet.Checksum = 0

	buffer := new(bytes.Buffer)
	binary.Write(buffer, binary.BigEndian, packet.SrcPort)
	binary.Write(buffer, binary.BigEndian, packet.DestPort)
	binary.Write(buffer, binary.BigEndian, packet.SeqNum)
	binary.Write(buffer, binary.BigEndian, packet.AckNum)
	binary.Write(buffer, binary.BigEndian, uint16(packet.DataOffset)<<12|uint16(packet.Flags))
	binary.Write(buffer, binary.BigEndian, packet.WindowSize)
	binary.Write(buffer, binary.BigEndian, packet.Checksum)
	binary.Write(buffer, binary.BigEndian, packet.Urgent)

	for _, option := range packet.Options {
		binary.Write(buffer, binary.BigEndian, option.Kind)
		if option.Length > 1 {
			binary.Write(buffer, binary.BigEndian, option.Length)
			binary.Write(buffer, binary.BigEndian, option.Data)
		}
	}

	if packet.Data != nil {
		binary.Write(buffer, binary.BigEndian, packet.Data)
	}

	output := buffer.Bytes()

	checksum := checksum(output, srcIP, dstIP)
	fmt.Printf("Checksum %d / 0x%x\n", checksum, checksum)

	output[16] = byte(checksum >> 8)
	output[17] = byte(checksum)

	return output
}

func (t *TCPPacket) String() string {
	return strings.Join([]string{
		"Source port: " + strconv.Itoa(int(t.SrcPort)),
		"Dest port:" + strconv.Itoa(int(t.DestPort)),
		"Sequence:" + strconv.Itoa(int(t.SeqNum)),
		"Acknowledgement:" + strconv.Itoa(int(t.AckNum)),
		"Header len:" + strconv.Itoa(int(t.DataOffset)),
		"Flags:" + fmt.Sprintf("%b", uint8(t.Flags)),
		"Flag ns:" + strconv.FormatBool(t.HasFlag(FlagNS)),
		"Flag crw:" + strconv.FormatBool(t.HasFlag(FlagCWR)),
		"Flag ece:" + strconv.FormatBool(t.HasFlag(FlagECE)),
		"Flag urg:" + strconv.FormatBool(t.HasFlag(FlagURG)),
		"Flag ack:" + strconv.FormatBool(t.HasFlag(FlagACK)),
		"Flag psh:" + strconv.FormatBool(t.HasFlag(FlagPSH)),
		"Flag rst:" + strconv.FormatBool(t.HasFlag(FlagRST)),
		"Flag syn:" + strconv.FormatBool(t.HasFlag(FlagSYN)),
		"Flag fin:" + strconv.FormatBool(t.HasFlag(FlagFIN)),

		"Window size:" + strconv.Itoa(int(t.WindowSize)),
		"Checksum:" + strconv.Itoa(int(t.Checksum)),
		"Urgent:" + strconv.Itoa(int(t.Urgent)),

		"Data:" + string(t.Data),
	}, "\n")
}

func checksum(tcpData []byte, srcIP, dstIP string) uint16 {
	length := uint16(len(tcpData))

	srcIPBytes := ipToBytes(srcIP)
	dstIPBytes := ipToBytes(dstIP)
	// pseudoHeader := []byte{
	// 	srcIPBytes[0], srcIPBytes[1], srcIPBytes[2], srcIPBytes[3],
	// 	dstIPBytes[0], dstIPBytes[1], dstIPBytes[2], dstIPBytes[3],
	// 	0,                               // zero
	// 	6,                               // protocol number (6 == TCP)
	// 	byte(length >> 8), byte(length), // TCP length (16 bits), not inc pseudo header
	// }

	// fullOutput := make([]byte, 0, len(pseudoHeader)+len(tcpData))
	// fullOutput = append(fullOutput, pseudoHeader...)
	// fullOutput = append(fullOutput, tcpData...)
	// dump(fullOutput)

	buffer := new(bytes.Buffer)
	binary.Write(buffer, binary.BigEndian, srcIPBytes)
	binary.Write(buffer, binary.BigEndian, dstIPBytes)
	binary.Write(buffer, binary.BigEndian, byte(0))
	binary.Write(buffer, binary.BigEndian, byte(6))
	binary.Write(buffer, binary.BigEndian, length)
	binary.Write(buffer, binary.BigEndian, tcpData)

	fullOutput := buffer.Bytes()
	fullLength := len(fullOutput)

	var word uint16
	var sum uint32
	for i := 0; i+1 < fullLength; i += 2 {
		word = uint16(fullOutput[i])<<8 | uint16(fullOutput[i+1])
		sum += uint32(word)
	}
	if fullLength%2 != 0 {
		sum += uint32(fullOutput[fullLength-1])
	}

	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	// Bitwise complement
	return uint16(^sum)
}

func ipToBytes(ip string) [4]byte {
	parts := strings.Split(ip, ".")
	b0, _ := strconv.Atoi(parts[0])
	b1, _ := strconv.Atoi(parts[1])
	b2, _ := strconv.Atoi(parts[2])
	b3, _ := strconv.Atoi(parts[3])
	return [4]byte{byte(b0), byte(b1), byte(b2), byte(b3)}
}

func Flag(set uint8, flag uint8, value bool) uint8 {
	if value {
		return set | (1 << flag)
	}
	return set &^ (1 << flag)
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalln("Usage : sudo TeaCP <dest address> <port>")
	}
	destIP := os.Args[1]
	port, _ := strconv.Atoi(os.Args[2])
	destPort := uint16(port)
	fmt.Println("Use", destIP, destPort)

	srcIP, _ := net.ResolveIPAddr("ip4", "10.12.0.1")
	dstIP, _ := net.ResolveIPAddr("ip4", destIP)

	sourcePort := uint16(55897)

	conn := NewTunIPConn(srcIP, dstIP)

	err := conn.Open()
	if err != nil {
		log.Fatalln("Error while opening opening TunIPConn", err)
	}
	defer conn.Close()

	fmt.Println("Interface opened. Pause while setup.")
	fmt.Println("Try: sudo ifconfig tun11 10.12.0.2 10.12.0.1")
	fmt.Print("Press 'Enter' to continue...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
	fmt.Println("GO !")

	packet := &TCPPacket{}
	packet.SrcPort = sourcePort
	packet.DestPort = destPort
	packet.DataOffset = uint8(5)
	packet.SetFlag(FlagSYN)
	packet.SeqNum = uint32(rand.Int())
	packet.AckNum = 0
	packet.WindowSize = uint16(4096 * 8)

	bytes := packet.Marshall("10.12.0.1", dstIP.IP.String())
	fmt.Println("TCP Output len:", len(bytes))

	length, err := conn.Write(bytes)
	if err != nil {
		log.Fatalln("Error while sending SYN TCP Packet:", err)
	}
	fmt.Printf("%d bytes sent (TCP Seq:%d, Ack:%d)\n", length, packet.SeqNum, packet.AckNum)

	//Receive SYN+ACK
	buffer := make([]byte, 4096*16)
	length, err = conn.Read(buffer)
	if err != nil {
		log.Fatalln("Error while reading tun interface", err)
	}
	fmt.Println(length, "bytes read")
	//dump(buffer[:length])

	responseTcp := NewTCPPacket(buffer[:length])
	fmt.Println("")
	fmt.Println("TCP Packet")
	fmt.Println(responseTcp.String())

	//SEND ACK
	packet = &TCPPacket{}
	packet.SrcPort = sourcePort
	packet.DestPort = destPort
	packet.DataOffset = uint8(5)
	packet.SetFlag(FlagACK)
	packet.SeqNum = responseTcp.AckNum
	packet.AckNum = responseTcp.SeqNum + 1
	packet.WindowSize = uint16(4096 * 8)

	bytes = packet.Marshall("10.12.0.1", dstIP.IP.String())
	fmt.Println("TCP Output len:", len(bytes))

	length, err = conn.Write(bytes)
	if err != nil {
		log.Fatalln("Error while sending SYN TCP Packet:", err)
	}
	fmt.Printf("%d bytes sent (TCP Seq:%d, Ack:%d)\n", length, packet.SeqNum, packet.AckNum)

	lastAck := packet.AckNum

	//Send REQUEST
	packet = &TCPPacket{}
	packet.SrcPort = sourcePort
	packet.DestPort = destPort
	packet.DataOffset = uint8(5)
	packet.SetFlag(FlagACK)
	packet.SetFlag(FlagPSH)
	packet.SeqNum = responseTcp.AckNum
	packet.AckNum = responseTcp.SeqNum + 1
	packet.WindowSize = uint16(4096 * 8)

	packet.Data = []byte("GET /hello HTTP/1.1\r\nHost: 192.168.10.170:8080\r\n\r\n")

	bytes = packet.Marshall("10.12.0.1", dstIP.IP.String())
	fmt.Println("TCP Output len:", len(bytes))

	length, err = conn.Write(bytes)
	if err != nil {
		log.Fatalln("Error while sending SYN TCP Packet:", err)
	}
	fmt.Printf("%d bytes sent (TCP Seq:%d, Ack:%d)\n", length, packet.SeqNum, packet.AckNum)

	//Receive response
	for {
		buffer = make([]byte, 4096*16)
		length, err = conn.Read(buffer)
		if err != nil {
			log.Fatalln("Error while reading tun interface", err)
		}
		fmt.Println(length, "bytes read")
		//dump(buffer[:length])

		responseTcp = NewTCPPacket(buffer[:length])
		fmt.Println("")
		fmt.Println("TCP Packet")
		fmt.Println(responseTcp.String())

		if lastAck == responseTcp.SeqNum+uint32(len(responseTcp.Data)) {
			continue
		}

		//SEND ACK
		packet = &TCPPacket{}
		packet.SrcPort = sourcePort
		packet.DestPort = destPort
		packet.DataOffset = uint8(5)
		packet.SetFlag(FlagACK)
		packet.SeqNum = responseTcp.AckNum
		packet.AckNum = responseTcp.SeqNum + uint32(len(responseTcp.Data))
		packet.WindowSize = uint16(4096 * 8)

		bytes = packet.Marshall("10.12.0.1", dstIP.IP.String())
		fmt.Println("TCP Output len:", len(bytes))

		length, err = conn.Write(bytes)
		if err != nil {
			log.Fatalln("Error while sending SYN TCP Packet:", err)
		}
		fmt.Printf("%d bytes sent (TCP Seq:%d, Ack:%d)\n", length, packet.SeqNum, packet.AckNum)
		lastAck = packet.AckNum

	}

	fmt.Print("Press 'Enter' to continue...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}

func dump(bytes []byte) {
	linesCount := 1
	for i := 0; i < len(bytes); i++ {
		if (i % 4) == 0 {
			fmt.Printf("%2d - ", linesCount)
			linesCount++
		}
		fmt.Printf("%08b", bytes[i])
		if (i+1)%4 == 0 {
			fmt.Printf("\n")
		} else {
			fmt.Printf(" ")
		}
	}
}
