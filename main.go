package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"strings"

	"golang.org/x/crypto/ssh"
)

type Connection struct {
	*ssh.Client
	password string
}

func Connect(addr, user, password string) (*Connection, error) {
	sshConfig := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }),
	}

	conn, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return nil, err
	}

	return &Connection{conn, password}, nil

}

func (conn *Connection) SendCommands(cmds string) ([]byte, error) {
	session, err := conn.NewSession()
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	err = session.RequestPty("xterm", 80, 40, modes)
	if err != nil {
		return []byte{}, err
	}

	stdoutB := new(bytes.Buffer)
	session.Stdout = stdoutB
	in, _ := session.StdinPipe()

	go func(in io.Writer, output *bytes.Buffer) {
		for {
			if strings.Contains(string(output.Bytes()), "[sudo] password for ") {
				_, err = in.Write([]byte(conn.password + "\n"))
				if err != nil {
					break
				}
				fmt.Println("put the password ---  end .")
				break
			}
		}
	}(in, stdoutB)

	err = session.Run(cmds)
	if err != nil {
		return []byte{}, err
	}
	return stdoutB.Bytes(), nil
}

func main() {
	// ssh refers to the custom package above
	conn, err := Connect("0.0.0.0:22", "username", "password")
	if err != nil {
		log.Fatal(err)
	}

	output, err := conn.SendCommands("sudo docker ps")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(output))

}
