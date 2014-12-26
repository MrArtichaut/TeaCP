package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sort"
	"sync"
	"time"
)

type TeaCPConn struct {
	ipConn        *TunIPConn
	localIPAddr   *net.IPAddr
	remoteIPAddr  *net.IPAddr
	destPort      uint16
	sourcePort    uint16
	seqNumber     uint32
	nextRemoteSeq uint32

	toAckQueue       []*TCPPacket
	toAckQueueLocker sync.Mutex

	buffer        bytes.Buffer
	buffReadCond  *sync.Cond
	buffWriteCond *sync.Cond
}

func DialTeaCP(localAddr, remoteAddr *net.IPAddr, destPort int) (*TeaCPConn, error) {
	conn := &TeaCPConn{
		localIPAddr:  localAddr,
		remoteIPAddr: remoteAddr,
		destPort:     uint16(destPort)}

	err := conn.open()
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (t *TeaCPConn) open() error {
	rand.Seed(time.Now().Unix())
	t.sourcePort = uint16(rand.Int())

	t.ipConn = NewTunIPConn(t.localIPAddr, t.remoteIPAddr)

	err := t.ipConn.Open()
	if err != nil {
		return err
	}

	fmt.Println("Interface opened. Pause while setup.")
	fmt.Println("Try: sudo ifconfig tun12 10.12.0.2 10.12.0.1")
	fmt.Print("Press 'Enter' to continue...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
	fmt.Println("GO !")

	packet := &TCPPacket{}
	packet.SrcPort = t.sourcePort
	packet.DestPort = t.destPort
	packet.DataOffset = uint8(5)
	packet.SetFlag(FlagSYN)
	packet.SeqNum = uint32(rand.Int())
	packet.AckNum = 0
	packet.WindowSize = uint16(4096 * 8)

	b := packet.Marshall(t.localIPAddr.String(), t.remoteIPAddr.IP.String())
	fmt.Println("TCP Output len:", len(b))

	length, err := t.ipConn.Write(b)
	if err != nil {
		fmt.Println("Error while sending SYN TCP Packet:", err)
		return err
	}
	fmt.Printf("%d bytes sent (TCP Seq:%d, Ack:%d)\n", length, packet.SeqNum, packet.AckNum)

	//Receive SYN+ACK
	buffer := make([]byte, 4096*16)
	length, err = t.ipConn.Read(buffer)
	if err != nil {
		fmt.Println("Error while reading tun interface", err)
		return err
	}
	fmt.Println(length, "bytes read")
	//dump(buffer[:length])

	responseTcp := NewTCPPacket(buffer[:length])
	fmt.Println("")
	fmt.Println("TCP Packet")
	fmt.Println(responseTcp.String())

	if !responseTcp.HasFlag(FlagSYN) || responseTcp.HasFlag(FlagACK) {
		return errors.New("Connection refused")
	}

	//SEND ACK
	packet = &TCPPacket{}
	packet.SrcPort = t.sourcePort
	packet.DestPort = t.destPort
	packet.DataOffset = uint8(5)
	packet.SetFlag(FlagACK)
	packet.SeqNum = responseTcp.AckNum
	packet.AckNum = responseTcp.SeqNum + 1
	packet.WindowSize = uint16(4096 * 8)

	b = packet.Marshall(t.localIPAddr.String(), t.remoteIPAddr.IP.String())
	fmt.Println("TCP Output len:", len(b))

	length, err = t.ipConn.Write(b)
	if err != nil {
		fmt.Println("Error while sending SYN TCP Packet:", err)
		return err
	}
	fmt.Printf("%d bytes sent (TCP Seq:%d, Ack:%d)\n", length, packet.SeqNum, packet.AckNum)

	t.nextRemoteSeq = packet.AckNum
	t.seqNumber = packet.SeqNum

	t.buffReadCond = sync.NewCond(new(sync.Mutex))
	t.buffWriteCond = sync.NewCond(new(sync.Mutex))
	t.buffer = bytes.Buffer{}

	return nil
}

func (t *TeaCPConn) consumePackects() {
	windowSize := 65535

	b := make([]byte, 65535)

	for {
		n, err := t.ipConn.Read(b)
		if err != nil {
			//close ?
			fmt.Println("IP Read error", err)
			continue
		}

		packet := NewTCPPacket(b)

		if packet.HasFlag(FlagRST) {
			//Clear buffer
			//Send ACK + RST
			return
		}

		if packet.SeqNum < t.nextRemoteSeq {
			continue // duplicate. Drop it
		}

		t.toAckQueue = append(t.toAckQueue, packet)

		t.buffWriteCond.L.Lock()
		if (windowSize - t.buffer.Len()) < n {
			//Not enought space in buffer. Wait
			t.buffWriteCond.Wait()
		}
		t.buffWriteCond.L.Unlock()

		t.buffReadCond.L.Lock()
		t.buffer.Write(b[:n])
		fmt.Println(n, "bytes written in TCP buffer")
		t.buffReadCond.Signal()
		t.buffReadCond.L.Unlock()
	}

}

type SortBySeq []*TCPPacket

func (a SortBySeq) Len() int {
	return len(a)
}
func (a SortBySeq) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}
func (a SortBySeq) Less(i, j int) bool {
	return a[i].SeqNum < a[j].SeqNum
}

// func sortQueue(q *list.List) {
//  last := q.Back()
//  for {
//    swapped := false
//    for e := q.Front(); e != last.Next(); e = e.Next() {
//      if e.Value.(*TCPPacket).SeqNum > e.Next().Value.(*TCPPacket).SeqNum {
//        q.MoveAfter(e, e.Next())
//        swapped = true
//      }
//    }
//    last = last.Prev()

//    if swapped == false || last == nil {
//      return
//    }
//  }
// }

func (t *TeaCPConn) ackPackets() {
	t.toAckQueueLocker.Lock()
	defer t.toAckQueueLocker.Unlock()

	if len(t.toAckQueue) == 0 {
		return
	}

	sort.Sort(SortBySeq(t.toAckQueue))

	var packetToAck *TCPPacket = t.toAckQueue[0]

	if packetToAck.SeqNum != t.nextRemoteSeq {
		//missing packet. Ack nothing (improvement : selective ACK)
		//clear toAckQueue
	}

	for i, p := range t.toAckQueue {
		expected := packetToAck.SeqNum
		if packetToAck.Data != nil {
			expected += uint32(len(packetToAck.Data))
		}

		if expected != p.SeqNum {
			//wrong sequence number (missing packet)
			t.toAckQueue = t.toAckQueue[:i]
			break
		}
		packetToAck = p
	}

	ackNumber := packetToAck.SeqNum
	if packetToAck.Data != nil {
		ackNumber += uint32(len(packetToAck.Data))
	}

}

func (t *TeaCPConn) Close() {

}

func (t *TeaCPConn) Read(b []byte) (n int, err error) {
	t.buffReadCond.L.Lock()
	if t.buffer.Len() == 0 {
		t.buffReadCond.Wait()
	}

	n, err = t.buffer.Read(b)
	t.buffReadCond.L.Unlock()

	return n, err
}
