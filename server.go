package main

import (
	"fmt"
	"log"
	"net"
	"os"
)

func handleTcpConnection(conn net.Conn) {
	for i := 0; i < 10; i++ {
		b := []byte(fmt.Sprint("TEST DATA N", i))
		l, err := conn.Write(b)
		if err != nil {
			fmt.Println("Error while sending payload ", i, " : ", err)
		} else {
			fmt.Println("Payload ", i, "sent ", l)
		}
	}

	conn.Close()
}

func main() {

	//http.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
	//	fmt.Println("Incoming request")
	//	fmt.Fprintf(w, "[{'id':1,'name':'Jean paul','token':null,'device':null},{'id':2,'name':'TOto tutu','token':null,'device':null},{'id':3,'name':'Tom Chaise','token':null,'device':null}]")
	//})

	//err := http.ListenAndServe("172.16.31.69:8080", nil)
	//if err != nil {
	//	log.Fatal("ListenAndServe: ", err)
	//}

	if len(os.Args) < 2 {
		log.Fatalln("Usage : sudo server <bind address> <port>")
	}
	localAddr := os.Args[1]
	port := os.Args[2]

	bindAddr, err := net.ResolveTCPAddr("tcp", localAddr+":"+port)
	if err != nil {
		log.Fatal("Fail to resolve bind addr ", localAddr, ":", port, " : ", err)
	}

	listener, err := net.ListenTCP("tcp", bindAddr)
	if err != nil {
		log.Fatal("Fail to listen for TCP connection : ", err)
	}

	fmt.Println("Listening for new connection with bind addr", bindAddr)
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			fmt.Println("Fail to accept TCP connection : ", err)
		} else {
			fmt.Println("New TCP connection accepted with", tcpConn.RemoteAddr())
			go handleTcpConnection(tcpConn)
		}
	}

	defer listener.Close()

}
