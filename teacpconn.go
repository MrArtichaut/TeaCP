package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sync"
	"time"
)

type TeaCPConn struct {
	ipConn          *TunIPConn
	localIPAddr     *net.IPAddr
	remoteIPAddr    *net.IPAddr
	destPort        uint16
	sourcePort      uint16
	localSeqNumber  uint32
	remoteSeqNumber uint32

	lastSentAck     uint32
	lastReceivedAck uint32

	sendBuffer       [][]byte
	sendCond         *sync.Cond
	ackWaitingBuffer []*TCPPacket

	rcvBuffer     *bytes.Buffer
	oooRcvPackets []*TCPPacket //Out of Order packets
	rcvBufferCon  *sync.Cond
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
	fmt.Println("Try: sudo ifconfig tun11 10.12.0.2 10.12.0.1")
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

	if !(responseTcp.HasFlag(FlagSYN) && responseTcp.HasFlag(FlagACK)) {
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

	t.remoteSeqNumber = packet.AckNum
	t.localSeqNumber = packet.SeqNum
	t.lastSentAck = packet.AckNum
	t.lastReceivedAck = t.localSeqNumber
	t.ackWaitingBuffer = make([]*TCPPacket, 10)
	t.rcvBuffer = new(bytes.Buffer)
	t.sendCond = sync.NewCond(new(sync.Mutex))
	t.rcvBufferCon = sync.NewCond(new(sync.Mutex))

	go t.packerSender()
	go t.packetsReceiver()

	return nil
}

func (t *TeaCPConn) packerSender() {
	localIp, remotetIp := t.localIPAddr.String(), t.remoteIPAddr.String()

	fmt.Println("O: packet sender started")
	for {
		t.sendCond.L.Lock()
		var flags uint16
		var payload []byte

		for {
			if t.remoteSeqNumber > t.lastSentAck {
				fmt.Println("O: remote seq num incremented. Send ack")
				flags = (1 << FlagACK)
				break
			} else if len(t.sendBuffer) > 0 {
				payload, t.sendBuffer = t.sendBuffer[len(t.sendBuffer)-1], t.sendBuffer[:len(t.sendBuffer)-1]
				break
			}
			t.sendCond.Wait()
		}
		t.sendCond.L.Unlock()

		p := t.sendPacket(flags, payload, localIp, remotetIp)
		fmt.Println("O: Packet sent")
		fmt.Println(p)
	}
}

func (t *TeaCPConn) sendPacket(flags uint16, payload []byte, localIp, remotetIp string) *TCPPacket {
	packet := &TCPPacket{}
	packet.SrcPort = t.sourcePort
	packet.DestPort = t.destPort
	packet.DataOffset = uint8(5)
	packet.SeqNum = t.localSeqNumber
	packet.AckNum = t.remoteSeqNumber
	packet.WindowSize = uint16(4096 * 8)

	packet.Flags = flags
	packet.Data = payload

	b := packet.Marshall(localIp, remotetIp)
	_, err := t.ipConn.Write(b)
	if err != nil {
		fmt.Println("Failed to send packet with seq", t.localSeqNumber, " due to error: ", err)
		//What to do ?
	} else {
		//start timeout timer
		if packet.HasFlag(FlagACK) {
			t.lastSentAck = packet.AckNum
		}

		if packet.Data != nil {
			t.localSeqNumber = t.localSeqNumber + uint32(len(packet.Data))
		}
	}

	return packet
}

func (t *TeaCPConn) packetsReceiver() {
	//windowSize := 65535

	b := make([]byte, 65535)

	fmt.Println("I: packet sender started")
	for {
		n, err := t.ipConn.Read(b)
		if err != nil {
			//close ?
			fmt.Println("IP Read error", err)
			continue
		}
		fmt.Println("I: ", n, "bytes read from ip connection")

		packet := NewTCPPacket(b)
		fmt.Println("I: New packet received")
		fmt.Println(packet)

		if packet.HasFlag(FlagRST) {
			fmt.Println("I: RST flag received")
			//Clear buffer
			//Send ACK + RST
			return
		}

		if packet.SeqNum < t.remoteSeqNumber {
			fmt.Println("I: Duplicate package. Retransmission ?")
			continue // duplicate packet. Drop it
		}

		if packet.HasFlag(FlagACK) {
			fmt.Println("I: ACK flag received")
			//var clean []*TCPPacket
			//for index, p := range t.ackWaitingBuffer {
			//	if (p.SeqNum + uint32(len(packet.Data))) > packet.AckNum {
			//		clean = append(clean, p)
			//	}
			//}
			//t.ackWaitingBuffer = clean

			////TODO
			//if len(packet.Data) == 0 {
			//	continue //Just an ACK packet, no reason to keep it
			//}
		}

		if packet.SeqNum > t.remoteSeqNumber {
			fmt.Println("I: Out of order packet")
			//t.oooRcvPackets = append(t.oooRcvPackets, packet) //TODO check rcv + ooo size first
			continue
		}

		t.rcvBufferCon.L.Lock()
		l, err := t.rcvBuffer.Write(packet.Data)
		if err != nil {
			fmt.Println("I: Error while writing packet data into buffer")
		} else {
			fmt.Println("I: ", l, "bytes writed into rcvBuffer")
			t.rcvBufferCon.Signal()
		}
		t.rcvBufferCon.L.Unlock()

		t.sendCond.L.Lock()
		t.remoteSeqNumber = t.remoteSeqNumber + uint32(len(packet.Data))
		fmt.Println("I: new remote seq num", t.remoteSeqNumber)
		t.sendCond.Signal() //signal that new ack should be send
		t.sendCond.L.Unlock()

		//if len(t.oooRcvPackets) > 0 {
		//	index := 0
		//	for {
		//		if index >= len(t.oooRcvPackets) {
		//			break
		//		}

		//		ooopacket := t.oooRcvPackets[index]
		//		if ooopacket.SeqNum == t.remoteSeqNumber {
		//			t.rcvBuffer = append(t.rcvBuffer, ooopacket)
		//			t.remoteSeqNumber = t.remoteSeqNumber + uint32(len(ooopacket.Data))
		//			t.oooRcvPackets = append(t.oooRcvPackets[:index], t.oooRcvPackets[index+1:]...)
		//			index = 0
		//		} else {
		//			index++
		//		}
		//	}
		//}

	}

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

func (t *TeaCPConn) Close() {

}

func (t *TeaCPConn) Read(b []byte) (n int, err error) {
	t.rcvBufferCon.L.Lock()
	if t.rcvBuffer.Len() == 0 {
		t.rcvBufferCon.Wait()
	}

	n, err = t.rcvBuffer.Read(b)
	t.rcvBufferCon.L.Unlock()

	return n, err
}
