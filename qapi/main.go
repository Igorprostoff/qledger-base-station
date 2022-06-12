package main

import (

	"html/template"
	"log"
	"net/http"

)

type tableLine struct{
	Id uint64
	Timestamp string
	Author string
	Data string
	Signature string
}
/*
func handler(w http.ResponseWriter, r *http.Request) {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	response, err := http.Get("https://192.168.1.84")
	if err != nil {
		log.Println("ERROR GET REQ,",err.Error())
		return
	}
	defer response.Body.Close() 
	var bWriter bytes.Buffer
   	io.Copy(&bWriter, response.Body)
	
	var data []tableLine

	fullength := uint64(len(bWriter.Bytes()))
	var readBytes uint64
	readBytes = 0
	resBytes := bWriter.Bytes()
	for fullength>readBytes {
		blockId := uint64(resBytes[0]) |
					uint64(resBytes[1])<<8 |
					uint64(resBytes[2])<<16|
					uint64(resBytes[3])<<24|
					uint64(resBytes[4])<<32|
					uint64(resBytes[5])<<40|
					uint64(resBytes[6])<<48|
					uint64(resBytes[7])<<56


		timestamp := uint64(resBytes[8]) |
		uint64(resBytes[9])<<8 |
		uint64(resBytes[10])<<16|
		uint64(resBytes[11])<<24|
		uint64(resBytes[12])<<32|
		uint64(resBytes[13])<<40|
		uint64(resBytes[14])<<48|
		uint64(resBytes[15])<<56

		dataSize := uint64(resBytes[16]) |
		uint64(resBytes[17])<<8 |
		uint64(resBytes[18])<<16|
		uint64(resBytes[19])<<24|
		uint64(resBytes[20])<<32|
		uint64(resBytes[21])<<40|
		uint64(resBytes[22])<<48|
		uint64(resBytes[23])<<56

		strData := resBytes[24:24+dataSize]

		par1sigsize := uint64(resBytes[24+dataSize]) |
		uint64(resBytes[24+dataSize+1])<<8 |
		uint64(resBytes[24+dataSize+2])<<16|
		uint64(resBytes[24+dataSize+3])<<24|
		uint64(resBytes[24+dataSize+4])<<32|
		uint64(resBytes[24+dataSize+5])<<40|
		uint64(resBytes[24+dataSize+6])<<48|
		uint64(resBytes[24+dataSize+7])<<56

		par2sigsize := uint64(resBytes[24+dataSize+8+par1sigsize]) |
		uint64(resBytes[24+dataSize+8+par1sigsize+1])<<8 |
		uint64(resBytes[24+dataSize+8+par1sigsize+2])<<16|
		uint64(resBytes[24+dataSize+8+par1sigsize+3])<<24|
		uint64(resBytes[24+dataSize+8+par1sigsize+4])<<32|
		uint64(resBytes[24+dataSize+8+par1sigsize+5])<<40|
		uint64(resBytes[24+dataSize+8+par1sigsize+6])<<48|
		uint64(resBytes[24+dataSize+8+par1sigsize+7])<<56

		strDeviceName := resBytes[24+dataSize+8+par1sigsize+8+par2sigsize:24+dataSize+8+par1sigsize+8+par2sigsize+5]
	
		sigSize := uint64(resBytes[24+dataSize+8+par1sigsize+8+par2sigsize+6]) |
				uint64(resBytes[24+dataSize+8+par1sigsize+8+par2sigsize+6+1])<<8 |
				uint64(resBytes[24+dataSize+8+par1sigsize+8+par2sigsize+6+2])<<16|
				uint64(resBytes[24+dataSize+8+par1sigsize+8+par2sigsize+6+3])<<24|
				uint64(resBytes[24+dataSize+8+par1sigsize+8+par2sigsize+6+4])<<32|
				uint64(resBytes[24+dataSize+8+par1sigsize+8+par2sigsize+6+5])<<40|
				uint64(resBytes[24+dataSize+8+par1sigsize+8+par2sigsize+6+6])<<48|
				uint64(resBytes[24+dataSize+8+par1sigsize+8+par2sigsize+6+7])<<56
		
		signature := fmt.Sprintf("%x", resBytes[24+dataSize+8+par1sigsize+8+par2sigsize+6+8:24+dataSize+8+par1sigsize+8+par2sigsize+6+8+sigSize]) 
		data = append(data, tableLine{blockId, timestamp,string(strDeviceName),string(strData),string(signature)}) 
	
		resBytes = resBytes[24+dataSize+8+par1sigsize+8+par2sigsize+6+8+sigSize:]
		readBytes += 24+dataSize+8+par1sigsize+8+par2sigsize+6+8+sigSize
	}
	//log.Println(data)

	tmpl, _ := template.ParseFiles("index.html")
    tmpl.Execute(w, data)
}
*/

func handler(w http.ResponseWriter, r *http.Request){
	tmpl, _ := template.ParseFiles("login.html")
    tmpl.Execute(w, nil)
}

func main()  {
	log.Println("WELCOME TO QLedger webapp")
	http.HandleFunc("/", handler)
	
	log.Fatal(http.ListenAndServe(":443", nil))
}