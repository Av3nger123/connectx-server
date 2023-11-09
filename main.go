package main

import (
	"bufio"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os/exec"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return r.Header.Get("Origin") == "http://localhost:3000"
	},
}

func sshClient(username string, signer ssh.Signer, remoteAddr string) (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", remoteAddr, config)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func sshClientLOCAL(username, password, remoteAddr string) (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User: "user",
		Auth: []ssh.AuthMethod{
			ssh.Password("1358"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", remoteAddr, config)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func handlerShellOutput(outputChannel chan string, reader io.Reader) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		outputChannel <- scanner.Text()
	}
}

func handleMessage(session *ssh.Session, message string) []byte {

	output, err := session.CombinedOutput(message)
	if err != nil {
		log.Printf("Failed to start SSH session with command: %s, Error: %v", message, err)
		return nil
	}
	return output
}

func getSSHSession() {

}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {

	// Websocket Connection
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}
	defer conn.Close()

	username := "ec2-user"
	// password := os.Getenv("PASSWORD")
	remoteAddr := "uat.liveolympiad.app:22"
	fileBytes, err := ioutil.ReadFile("../../.ssh/id_rsa")
	if err != nil {
		log.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(fileBytes)
	if err != nil {
		log.Fatalf("parse key failed:%v", err)
	}

	// SSH Client Connection
	client, err := sshClient(username, signer, remoteAddr)
	// client, err := sshClientLOCAL(username, password, remoteAddr)
	if err != nil {
		log.Printf("Failed to connect to the remote server: %v", err)
		return
	}
	log.Println("Client Connected")
	defer client.Close()

	// SSH Client Session
	session, err := client.NewSession()
	if err != nil {
		log.Fatalln(err.Error())
		return
	}
	defer session.Close()

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Printf("WebSocket read error: %v", err.Error())
			return
		}
		output := handleMessage(session, string(message))
		log.Printf("Command Output:\n%s", output)
		err = conn.WriteMessage(websocket.TextMessage, []byte(string(output)))
		if err != nil {
			log.Println("Websocket write error")
		}
	}

}

func runCommand(command string) ([]byte, error) {
	cmd := exec.Command(command)
	output, err := cmd.CombinedOutput()
	return output, err
}

func main() {

	http.HandleFunc("/ssh", handleWebSocket)

	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
