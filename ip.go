package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func FD_SET(i int, p *syscall.FdSet) {
	p.Bits[i/64] |= 1 << uint(i) % 64
}

func FD_ISSET(i int, p *syscall.FdSet) bool {
	return (p.Bits[i/64] & (1 << uint(i) % 64)) != 0
}

func FD_ZERO(p *syscall.FdSet) {
	for i := range p.Bits {
		p.Bits[i] = 0
	}
}

type IPV4Packet struct {
	Version        uint8 //4 bits
	IHL            uint8 //4 bits
	DSCP           uint8 //6 bits
	ECN            uint8 //2 bits
	Length         uint16
	Identification uint16
	Flags          uint8  //3 bits
	FragOffset     uint16 //13 bit
	TTL            uint8
	Protocol       uint8
	Checksum       uint16
	SrcIp          uint32
	DstIp          uint32
	Options        []IPV4Option

	Payload []byte
}

type IPV4Option struct {
	OptionType uint8 // 1 bit Copied, 2 bits Option Class, 5 bits Option Number
	Length     uint8
	Data       []byte
}

func IPV4Payload(data []byte) []byte {
	ihl := uint8(data[0]) & 0xf
	headerLen := (int(ihl) * 32) / 8
	if len(data) == headerLen {
		return nil
	}
	return data[headerLen:]
}

func NewIPV4Packet(data []byte) *IPV4Packet {
	var p IPV4Packet
	reader := bytes.NewReader(data)

	var field uint8
	binary.Read(reader, binary.BigEndian, &field)
	p.Version = field >> 4
	p.IHL = field & 0xf

	binary.Read(reader, binary.BigEndian, &field)
	p.DSCP = uint8(field >> 2)
	p.ECN = uint8(field & 0x3)

	binary.Read(reader, binary.BigEndian, &p.Length)
	binary.Read(reader, binary.BigEndian, &p.Identification)

	var field16 uint16
	binary.Read(reader, binary.BigEndian, &field16)
	p.Flags = uint8(field16 >> 12)
	p.FragOffset = field16 & 0x1FFF

	binary.Read(reader, binary.BigEndian, &p.TTL)
	binary.Read(reader, binary.BigEndian, &p.Protocol)
	binary.Read(reader, binary.BigEndian, &p.Checksum)
	binary.Read(reader, binary.BigEndian, &p.SrcIp)
	binary.Read(reader, binary.BigEndian, &p.DstIp)

	if p.IHL > 5 {
		//Skip option for now
	}

	headerSize := uint16((p.IHL * 32) / 8)
	if p.Length > headerSize {
		p.Payload = data[headerSize:]
	}

	return &p
}

func (p *IPV4Packet) Serialize() []byte {
	p.Checksum = 0

	buffer := new(bytes.Buffer)
	binary.Write(buffer, binary.BigEndian, p.Version<<4|(p.IHL&0xf))
	binary.Write(buffer, binary.BigEndian, p.DSCP<<2|(p.ECN&0x3))
	binary.Write(buffer, binary.BigEndian, p.Length)
	binary.Write(buffer, binary.BigEndian, p.Identification)
	binary.Write(buffer, binary.BigEndian, uint16(p.Flags)<<12|(p.FragOffset&0x1FFF))
	binary.Write(buffer, binary.BigEndian, p.TTL)
	binary.Write(buffer, binary.BigEndian, p.Protocol)
	binary.Write(buffer, binary.BigEndian, p.Checksum)
	binary.Write(buffer, binary.BigEndian, p.SrcIp)
	binary.Write(buffer, binary.BigEndian, p.DstIp)

	for _, option := range p.Options {
		binary.Write(buffer, binary.BigEndian, option.OptionType)
		if option.Length > 1 {
			binary.Write(buffer, binary.BigEndian, option.Length)
			binary.Write(buffer, binary.BigEndian, option.Data)
		}
	}

	output := buffer.Bytes()

	checksum := ipChecksum(output)

	output[10] = byte(checksum >> 8)
	output[11] = byte(checksum)

	computed := ipChecksum(output)
	fmt.Printf("IP checksum (%x): %d\n", checksum, computed)

	if p.Payload != nil {
		binary.Write(buffer, binary.BigEndian, p.Payload)
		output = buffer.Bytes()
	}

	return output
}

func (p *IPV4Packet) String() string {
	return strings.Join([]string{
		"Version: " + strconv.Itoa(int(p.Version)),
		"IHL:" + strconv.Itoa(int(p.IHL)),
		"DSCP:" + strconv.Itoa(int(p.DSCP)),
		"ECN:" + strconv.Itoa(int(p.ECN)),
		"Total Len:" + strconv.Itoa(int(p.Length)),
		"Identification:" + strconv.Itoa(int(p.Identification)),
		"Flags:" + fmt.Sprintf("0x%x", p.Flags),
		"Fragment Offset:" + strconv.Itoa(int(p.FragOffset)),
		"TTL:" + strconv.Itoa(int(p.TTL)),
		"Protocol:" + strconv.Itoa(int(p.Protocol)),
		"Header Checksum:" + fmt.Sprintf("0x%x", p.Checksum),
		"IP Source:" + DecodeIPV4Addr(p.SrcIp),
		"IP Destination:" + DecodeIPV4Addr(p.DstIp),
		"Options:" + strconv.Itoa(len(p.Options)),

		"Data:" + strconv.Itoa(len(p.Payload)) + " bytes",
	}, "\n")
}

func IPV4AddrToInt(addr string) uint32 {
	parts := strings.Split(addr, ".")

	var ip uint32
	part, _ := strconv.Atoi(parts[0])
	ip |= uint32(part) << 24
	part, _ = strconv.Atoi(parts[1])
	ip |= uint32(part) << 16
	part, _ = strconv.Atoi(parts[2])
	ip |= uint32(part) << 8
	part, _ = strconv.Atoi(parts[3])
	ip |= uint32(part)

	return ip
}

func DecodeIPV4Addr(addr uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", (addr>>24)&0xff, (addr>>16)&0xff, (addr>>8)&0xff, addr&0xff)
}

func ipChecksum(ipBuffer []byte) uint16 {
	len := len(ipBuffer)

	var word uint16
	var sum uint32
	for i := 0; i+1 < len; i += 2 {
		word = uint16(ipBuffer[i])<<8 | uint16(ipBuffer[i+1])
		sum += uint32(word)
	}

	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	// Bitwise complement
	return uint16(^sum)
}

type TunIPConn struct {
	tunFile    *os.File
	localAddr  *net.IPAddr
	remoteAddr *net.IPAddr

	srcField uint32
	dstField uint32
}

func NewTunIPConn(localAddr, remoteAddr *net.IPAddr) *TunIPConn {
	srcField := IPV4AddrToInt(localAddr.IP.String())
	dstField := IPV4AddrToInt(remoteAddr.IP.String())

	return &TunIPConn{
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
		srcField:   srcField,
		dstField:   dstField}
}

func (c *TunIPConn) RemoteAddr() net.IPAddr {
	return *c.remoteAddr
}

func (c *TunIPConn) LocalAddr() net.IPAddr {
	return *c.localAddr
}

func (c *TunIPConn) Open() error {
	file, err := os.OpenFile("/dev/tun11", os.O_RDWR, 0)
	if err != nil {
		return err
	}

	c.tunFile = file
	return nil
}

func (c *TunIPConn) Close() error {
	err := c.tunFile.Close()
	if err != nil {
		return err
	}
	c.tunFile = nil
	return nil
}

func (c *TunIPConn) Write(data []byte) (n int, err error) {
	packet := &IPV4Packet{}
	packet.SrcIp = c.srcField
	packet.DstIp = c.dstField
	packet.Version = 4
	packet.IHL = 5
	packet.Length = uint16(20 + len(data))
	packet.Identification = uint16(rand.Int())
	packet.TTL = 64
	packet.Protocol = 6
	packet.Payload = data

	bytes := packet.Serialize()

	length, err := c.tunFile.Write(bytes)
	if err != nil {
		return -1, err
	}

	return length - (len(bytes) - len(data)), nil
}

func (c *TunIPConn) Read(b []byte) (n int, err error) {
	buffer := make([]byte, len(b)+60) //60 bytes : max IP Header's length

	fd := int(c.tunFile.Fd())
	readFdSet := new(syscall.FdSet)
	FD_SET(fd, readFdSet)

	timeout := syscall.NsecToTimeval(1000000000)

	e := syscall.Select(fd+1, readFdSet, nil, nil, &timeout)
	if e != nil {
		return -1, e
	}

	if !FD_ISSET(fd, readFdSet) {
		return -1, errors.New("Read timeout")
	}

	var packet *IPV4Packet
	var length int
	for {
		length, err = c.tunFile.Read(buffer)
		if err != nil {
			return -1, err
		}

		packet = NewIPV4Packet(buffer[:length])
		if packet.DstIp != c.srcField {
			log.Println("Unwanted IP packet with destination:", DecodeIPV4Addr(packet.DstIp))
		} else {
			break
		}
	}

	return copy(b, packet.Payload), nil
}
