package main

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

var (
	UserName         string
	PasswordHash     []byte
	Port             string
	Password         string // Used only for hash generation
	KeyFileName      string
	AuthKeysFileName string
	NoParallelCmds   bool

	config      *ssh.ServerConfig
	authKeysMap = make(map[string]bool)
	mu          sync.Mutex // protects from parallel commands execution
)

func main() {
	log.SetFlags(0)
	if err := initConfig(); err != nil {
		log.Fatal("Initialization failed: ", err)
	}
	if Password != "" {
		b, err := bcrypt.GenerateFromPassword([]byte(Password), bcrypt.DefaultCost)
		if err != nil {
			log.Fatal("Password hash generation failed: ", err)
		}
		fmt.Println(base64.StdEncoding.EncodeToString(b))
		return
	}
	if err := serve(); err != nil {
		log.Fatal("Service failed: ", err)
	}
}

func initConfig() error {
	flag.StringVar(&Password, "hash", "", "Generate hash of the given password")
	flag.StringVar(&Port, "p", "22", "Port number")
	flag.StringVar(&KeyFileName, "pkey", "id_rsa", "Private key file name")
	flag.StringVar(&AuthKeysFileName, "akeys", "authorized_keys", "Authorized keys file name")
	flag.BoolVar(&NoParallelCmds, "mu", false, "Disable parallel commands execution")

	flag.Parse()

	if _, err := strconv.ParseUint(Port, 10, 16); err != nil {
		return fmt.Errorf("port number has invalid format: %s", err)
	}
	if Password != "" {
		return nil
	}

	// password auth
	UserName = os.Getenv("USER_NAME")
	encodedPass := os.Getenv("PASSWORD_HASH")
	if UserName != "" && encodedPass == "" {
		return errors.New("password should be defined through PASSWORD_HASH env var")
	}
	b, err := base64.StdEncoding.DecodeString(encodedPass)
	if err != nil {
		return fmt.Errorf("unable to decode password hash: %s", err)
	}
	PasswordHash = b

	// keys auth
	if AuthKeysFileName != "" {
		authKeysBytes, err := ioutil.ReadFile(AuthKeysFileName)
		if err != nil {
			return fmt.Errorf("failed to load authorized keys: %s", err)
		}
		for len(authKeysBytes) > 0 {
			pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authKeysBytes)
			if err != nil {
				return fmt.Errorf("failed to parse authorized keys: %s", err)
			}
			authKeysMap[string(pubKey.Marshal())] = true
			authKeysBytes = rest
		}
	}

	config = &ssh.ServerConfig{
		PasswordCallback:  passwordAuth,
		PublicKeyCallback: keyAuth,
	}
	privateBytes, err := ioutil.ReadFile(KeyFileName)
	if err != nil {
		return fmt.Errorf("failed to load private key: %s", err)
	}
	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %s", err)
	}
	config.AddHostKey(private)
	return nil
}

func passwordAuth(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
	log.Printf("User '%s' login from %s with password", c.User(), c.RemoteAddr())
	if authenticateUser(c.User(), pass) {
		log.Printf("User '%s' accepted", c.User())
		return nil, nil
	}
	return nil, fmt.Errorf("password rejected for %q", c.User())
}

func authenticateUser(user string, pass []byte) bool {
	if UserName == "" {
		// password authentication disabled
		return false
	}
	if subtle.ConstantTimeCompare([]byte(user), []byte(UserName)) != 1 {
		log.Print("Invalid user name")
		return false
	}
	if err := bcrypt.CompareHashAndPassword(PasswordHash, pass); err != nil {
		log.Print("Invalid password: ", err)
		return false
	}
	return true
}

func keyAuth(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
	log.Printf("User '%s' login from %s with key", c.User(), c.RemoteAddr())
	if authKeysMap[string(pubKey.Marshal())] {
		log.Printf("User '%s' accepted", c.User())
		return nil, nil
	}
	return nil, fmt.Errorf("unknown public key for %q", c.User())
}

func serve() error {
	l, err := net.Listen("tcp", "0.0.0.0:"+Port)
	if err != nil {
		return fmt.Errorf("listen error: %s", err)
	}
	for {
		conn, err := l.Accept()
		log.Print("Incoming connection: ", conn.RemoteAddr())
		if err != nil {
			return fmt.Errorf("unable to accept incoming connections: %s", err)
		}
		_, chans, reqs, err := ssh.NewServerConn(conn, config)
		if err != nil {
			log.Print("Connection failed: ", err)
			continue
		}
		go ssh.DiscardRequests(reqs)
		go serveChannels(chans)
	}
}

func serveChannels(chans <-chan ssh.NewChannel) {
	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
			log.Printf("Channel %s rejected", newChan.ChannelType())
			continue
		}
		ch, reqs, err := newChan.Accept()
		if err != nil {
			log.Print("Unable to accept new ssh channel: ", err)
			continue
		}
		channel := &Channel{ch, reqs}
		go channel.serveRequests()
	}
}

type Channel struct {
	ssh.Channel
	Requests <-chan *ssh.Request
}

func (ch *Channel) serveRequests() {
	defer func() {
		log.Print("Close channel")
		ch.Close()
	}()
	for req := range ch.Requests {
		log.Printf("Request: %s, %s", req.Type, strconv.Quote(string(req.Payload)))
		switch req.Type {
		case "exec":
			ch.serveExecRequest(req.Payload)
			req.Reply(true, nil)
			return
			// TODO: response exit code
		default:
			req.Reply(false, nil)
		}
	}
}

func (ch *Channel) serveExecRequest(payload []byte) {
	stderr := ch.Stderr()
	if NoParallelCmds {
		fmt.Fprintln(stderr, "Server: Wait...")
		mu.Lock()
		fmt.Fprintln(stderr, "Server: Exec")
		defer mu.Unlock()
	}
	line := string(payload[4:])
	parts := strings.Split(line, " ")
	// TODO(yar): terminate command on ctrl+c
	cmd := exec.Command(parts[0], parts[1:]...)
	cmd.Stderr = stderr
	cmd.Stdout = ch
	if runtime.GOOS == "windows" {
		cmd.Stderr = newWindowsDecoder(cmd.Stderr)
		cmd.Stdout = newWindowsDecoder(cmd.Stdout)
	}
	// Next line locks command termination (see Stdin description)
	// TODO(yar): design proper implementation.
	// cmd.Stdin = ch
	if err := cmd.Run(); err != nil {
		log.Print("Command executing error: ", err)
		return
	}
	log.Print("Command executed")
}

type decoder struct {
	base io.Writer
	d    *encoding.Decoder
}

func newWindowsDecoder(w io.Writer) *decoder {
	// TODO(yar): implement able to select codepage (866 and maybe some other)
	return &decoder{w, charmap.Windows1251.NewDecoder()}
}

func (d *decoder) Write(p []byte) (n int, err error) {
	decoded, err := d.d.Bytes(p)
	if err != nil {
		return 0, err
	}
	n, err = d.base.Write(decoded)
	if err != nil {
		return 0, err
	}
	if n < len(p) {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}
