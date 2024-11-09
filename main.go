package main

import (
	"bytes"
	"crypto/subtle"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

type exitStatusMsg struct {
	Status uint32
}

// RFC 4254 Section 6.5.
type execMsg struct {
	Command string
}

var (
	password       = flag.String("pass", "", "SSH password")
	username       = flag.String("user", "root", "SSH username, default is root")
	port           = flag.String("port", "2222", "SSH port, default is 2222")
	privateKeyPath = flag.String("key", "ssh_host_rsa_key", "Path to private key file, default is ssh_host_rsa_key")
)

// getShellCommand returns the appropriate shell command based on OS
func getShellCommand() *exec.Cmd {
	if runtime.GOOS == "windows" {
		// Git Bash path on Windows
		return exec.Command("C:\\Program Files\\Git\\bin\\bash.exe", "--login", "-i")
	}
	// Default Unix/Linux shell
	return exec.Command("/bin/bash", "-i")
}

func handleConnection(nConn net.Conn, config *ssh.ServerConfig) {
	if nConn == nil {
		log.Println("nConn is nil")
		return
	}
	if config == nil {
		log.Println("config is nil")
		return
	}

	_, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		log.Printf("Failed to establish SSH connection: %v", err)
		return
	}

	log.Printf("New SSH connection from %s", nConn.RemoteAddr().String())

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("Could not accept channel: %v", err)
			continue
		}

		go handleRequests(channel, requests)
	}
}

func runExecCommand(command string, ch ssh.Channel) {
	cmd := exec.Command("/bin/bash", "-c", command)
	cmd.Stdout = ch
	cmd.Stderr = ch.Stderr()
	cmd.Stdin = ch
	cmd.Run()
	fmt.Println("exec command: ", command)
	ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
	ch.Close()
}

func handleRequests(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()

	var f *os.File
	var err error

	if runtime.GOOS == "windows" {
		cmd := exec.Command("C:\\Program Files\\Git\\bin\\bash.exe", "--login", "-i")

		// Setup working directory
		cmd.Dir = os.Getenv("USERPROFILE")

		// Enhanced environment variables
		cmd.Env = append(os.Environ(),
			"TERM=xterm-256color",
			"PATH=C:\\Program Files\\Git\\bin;C:\\Program Files\\Git\\usr\\bin;C:\\Program Files\\Git\\mingw64\\bin;"+os.Getenv("PATH"),
			"HOME="+os.Getenv("USERPROFILE"),
			"SHELL=C:\\Program Files\\Git\\bin\\bash.exe",
			"MSYSTEM=MINGW64",
			"CHERE_INVOKING=1",
			"PS1=\\[\\033[32m\\]\\u@\\h\\[\\033[0m\\]:\\[\\033[34m\\]\\w\\[\\033[0m\\]\\$ ", // Set colored prompt
		)

		// Setup pipes
		stdin, err := cmd.StdinPipe()
		if err != nil {
			log.Printf("Failed to create stdin pipe: %v", err)
			return
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			log.Printf("Failed to create stdout pipe: %v", err)
			return
		}
		stderr, err := cmd.StderrPipe()
		if err != nil {
			log.Printf("Failed to create stderr pipe: %v", err)
			return
		}

		// Start command
		if err := cmd.Start(); err != nil {
			log.Printf("Failed to start command: %v", err)
			return
		}

		// Handle SSH requests with proper terminal settings
		isInteractive := false
		go func() {
			for req := range requests {
				fmt.Printf("Request type %s\n", req.Type)
				switch req.Type {
				case "shell":
					isInteractive = true
					if isInteractive {
						stdin.Write([]byte("export TERM=xterm-256color\n"))
						stdin.Write([]byte("cd \"$HOME\"\n"))
						stdin.Write([]byte("clear\n"))
					}
					req.Reply(true, nil)
				case "pty-req":
					isInteractive = true
					termLen := req.Payload[3]
					w, h := parseDims(req.Payload[termLen+4:])
					log.Printf("Terminal size: %dx%d", w, h)
					req.Reply(true, nil)
				case "subsystem", "exec":
					channel.Write([]byte("Request of type subsystem or exec are not suppprted\n"))
					req.Reply(false, nil)
				case "window-change":
					if isInteractive {
						w, h := parseDims(req.Payload)
						log.Printf("Window size changed: %dx%d", w, h)
					}
				}
			}
		}()

		// Bidirectional communication for stdin
		go func() {
			io.Copy(stdin, channel)
			stdin.Close()
		}()

		// Handle stderr directly
		go func() {
			buf := make([]byte, 32*1024)
			for {
				nr, err := stderr.Read(buf)
				if nr > 0 {
					data := buf[:nr]
					lines := bytes.Split(data, []byte("\n"))

					for i, line := range lines {
						if i == len(lines)-1 {
							channel.Write(line)
							continue
						}
						channel.Write(append(line, '\r', '\n'))
					}
				}
				if err != nil {
					break
				}
			}
		}()

		// Handle stdout directly
		buf := make([]byte, 32*1024)
		for {
			nr, err := stdout.Read(buf)
			if nr > 0 {
				data := buf[:nr]
				lines := bytes.Split(data, []byte("\n"))

				channel.Write([]byte("\r"))
				for i, line := range lines {
					if i == len(lines)-1 {
						channel.Write(line)
						continue
					}
					channel.Write(append(line, '\r', '\n'))
				}
			}
			if err != nil {
				break
			}
		}

		cmd.Wait()
	} else {
		// Unix/Linux code
		isInteractive := false

		// Handle requests
		go func() {
			for req := range requests {
				fmt.Printf("Request type: %s\n", req.Type)
				switch req.Type {
				case "shell":
					isInteractive = true
					req.Reply(true, nil)
				case "pty-req":
					isInteractive = true
					termLen := req.Payload[3]
					w, h := parseDims(req.Payload[termLen+4:])
					term := string(req.Payload[4 : termLen+4])
					log.Printf("pty-req '%s' %dx%d", term, w, h)
					pty.Setsize(f, &pty.Winsize{
						Rows: uint16(h),
						Cols: uint16(w),
					})
					req.Reply(true, nil)
				case "subsystem":
					channel.Write([]byte("Request of type subsystem is not suppprted\n"))
					req.Reply(false, nil)
				case "exec":
					var msg execMsg
					if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
						log.Printf("error parsing ssh execMsg: %s\n", err)
						req.Reply(false, nil)
						return
					}
					fmt.Printf("Subsystem request: %s", msg.Command)
					go func(msg execMsg, ch ssh.Channel) {
						// ch can be used as a ReadWriteCloser if there should be interactivity
						runExecCommand(msg.Command, ch)
						ex := exitStatusMsg{
							Status: 0,
						}
						// return the status code
						if _, err := ch.SendRequest("exit-status", false, ssh.Marshal(&ex)); err != nil {
							log.Printf("unable to send status: %v", err)
						}
						ch.Close()
					}(msg, channel)
					req.Reply(true, nil) // tell the other end that we can run the request
				case "window-change":
					if isInteractive {
						w, h := parseDims(req.Payload)
						pty.Setsize(f, &pty.Winsize{
							Rows: uint16(h),
							Cols: uint16(w),
						})
					}
				}
			}
		}()

		if isInteractive {
			// Interactive session - use PTY
			cmd := getShellCommand()
			f, err = pty.Start(cmd)
			if err != nil {
				log.Printf("Failed to start shell: %v", err)
				return
			}
			defer f.Close()

			// Setup bidirectional communication
			go func() {
				io.Copy(f, channel)
				f.Close() // This will signal the process to terminate
			}()
			io.Copy(channel, f)
		}
	}
}

func parseDims(b []byte) (width, height int) {
	width = int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	height = int(b[4])<<24 | int(b[5])<<16 | int(b[6])<<8 | int(b[7])
	return
}

func main() {
	flag.Parse()

	if *username == "" || *password == "" {
		log.Fatal("Username and password are required. Use -user and -pass flags")
	}

	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == *username &&
				subtle.ConstantTimeCompare([]byte(*password), pass) == 1 {
				return nil, nil
			}
			return nil, fmt.Errorf("invalid credentials")
		},
	}

	privateBytes, err := os.ReadFile(*privateKeyPath)
	if err != nil {
		log.Fatal("Failed to load private key: ", err)
	}

	private, err := ssh.ParsePrivateKeyWithPassphrase(privateBytes, []byte("paulinagoto17"))
	if err != nil {
		log.Fatal("Failed to parse private key: ", err)
	}

	config.AddHostKey(private)

	host := fmt.Sprintf("0.0.0.0:%s", *port)

	listener, err := net.Listen("tcp", host)
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}
	log.Printf("Listening on %s... (OS: %s)", host, runtime.GOOS)

	for {
		nConn, err := listener.Accept()
		if err != nil {
			log.Fatal("failed to accept incoming connection: ", err)
		}

		go handleConnection(nConn, config)
	}
}
