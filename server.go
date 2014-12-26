package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {

	http.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Incoming request")
		fmt.Fprintf(w, "[{'id':1,'name':'Jean paul','token':null,'device':null},{'id':2,'name':'TOto tutu','token':null,'device':null},{'id':3,'name':'Tom Chaise','token':null,'device':null}]")
	})

	err := http.ListenAndServe("192.168.10.170:8080", nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}

}
