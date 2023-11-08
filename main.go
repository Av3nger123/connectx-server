package main

import (
	"bufio"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os/exec"

	"github.com/gin-gonic/gin"
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

func sshClientPEM(username string, signer ssh.Signer, remoteAddr string) (*ssh.Client, error) {
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

func handleWebsocket(session *ssh.Session, conn *websocket.Conn, message string) {
	log.Println("Message Recieved")
	// Start the SSH session
	err := session.Start(string(message))
	if err != nil {
		log.Printf("Failed to start SSH session: %v", err)
		return
	}

}

func runCommand(command string) ([]byte, error) {
	cmd := exec.Command(command)
	output, err := cmd.CombinedOutput()
	return output, err
}

func main() {
	r := gin.Default()

	r.GET("/ssh", func(c *gin.Context) {
		username := "ubuntu"
		// password := os.Getenv("PASSWORD")
		remoteAddr := "13.235.71.251:22"
		pemBytes, err := ioutil.ReadFile("../terraform/test")
		if err != nil {
			log.Fatal(err)
		}
		signer, err := ssh.ParsePrivateKey(pemBytes)
		if err != nil {
			log.Fatalf("parse key failed:%v", err)
		}

		// SSH Client Connection
		client, err := sshClientPEM(username, signer, remoteAddr)
		// client, err := sshClientLOCAL(username, password, remoteAddr)
		if err != nil {
			log.Printf("Failed to connect to the remote server: %v", err)
			return
		}
		log.Println("Client Connected")
		defer client.Close()

		// Websocket Connection
		conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			log.Printf("WebSocket upgrade error: %v", err)
			return
		}
		defer conn.Close()

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
				log.Printf("WebSocket read error: %v", err)
				return
			}
			// Set up pipes to capture standard output and standard error
			stdout, err := session.StdoutPipe()
			if err != nil {
				log.Printf("Failed to create stdout pipe: %v", err)
				return
			}
			stderr, err := session.StderrPipe()
			if err != nil {
				log.Printf("Failed to create stderr pipe: %v", err)
				return
			}

			// Create channels for collecting the output and errors
			output := make(chan string)
			errors := make(chan string)

			// Goroutine to collect and send the output to the WebSocket
			go handlerShellOutput(output, stdout)

			// Goroutine to collect and send the errors to the WebSocket
			go handlerShellOutput(errors, stderr)

			handleWebsocket(session, conn, string(message))

			for {
				select {
				case msg := <-output:
					if err := conn.WriteMessage(websocket.TextMessage, []byte("output: "+msg)); err != nil {
						log.Printf("WebSocket write error: %v", err)
						return
					}
				case msg := <-errors:
					if err := conn.WriteMessage(websocket.TextMessage, []byte("error: "+msg)); err != nil {
						log.Printf("WebSocket write error: %v", err)
						return
					}
				}
			}
		}

	})

	r.Run(":8080")
}
