package vlab

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"

	"github.com/tg123/sshpiper/sshpiperd/upstream"
	"golang.org/x/crypto/ssh"
)

var logger *log.Logger

type plugin struct {
}

func findUpstreamFromAPI(conn ssh.ConnMetadata, challengeContext ssh.AdditionalChallengeContext) (
	func(unixUsername string, key ssh.PublicKey, answers []string, data *ssh.AuthData) (net.Conn, error), *ssh.AuthPipe, error) {
	sshUser := conn.User()
	requireUnixPassword := !(sshUser == "root" || sshUser == "ubuntu" || sshUser == "vlab" || sshUser == "recovery" || sshUser == "console")

	interactiveQuestions := []string{"Vlab username (Student ID): ", "Vlab password: "}
	interactiveEcho := []bool{true, false}
	if requireUnixPassword {
		interactiveQuestions = append(interactiveQuestions, "UNIX password: ")
		interactiveEcho = append(interactiveEcho, false)
	}

	return func(unixUsername string, key ssh.PublicKey, answers []string, data *ssh.AuthData) (net.Conn, error) {
			var authType, pubkeyType, pubkeyData, username, password string
			if key != nil {
				pubkeyType = key.Type()
				pubkeyData = base64.StdEncoding.EncodeToString(key.Marshal())
				authType = "key"
			} else {
				if requireUnixPassword && len(answers) < 3 {
					return nil, errors.New("invalid auth answers")
				} else if !requireUnixPassword && len(answers) < 2 {
					return nil, errors.New("invalid auth answers")
				}
				username = answers[0]
				password = answers[1]
				if requireUnixPassword {
					data.HasSentPassword = true
					data.Password = []byte(answers[2])
				} else {
					data.HasSentPassword = false
					data.Password = nil
				}
				authType = "userpass"
			}
			type Request struct {
				AuthType      string `json:"auth_type"`
				Username      string `json:"username"`
				Password      string `json:"password"`
				UnixUsername  string `json:"unix_username"`
				PublicKeyType string `json:"public_key_type"`
				PublicKeyData string `json:"public_key_data"`
				Token         string `json:"token"`
			}
			request := Request{
				AuthType:      authType,
				Username:      username,
				Password:      password,
				UnixUsername:  unixUsername,
				PublicKeyType: pubkeyType,
				PublicKeyData: pubkeyData,
				Token:         config.Token,
			}
			jsonData, err := json.Marshal(request)
			if err != nil {
				return nil, err
			}
			res, err := http.Post(config.API, "application/json", bytes.NewBuffer(jsonData))
			if err != nil {
				return nil, err
			}
			defer res.Body.Close()
			body, err := ioutil.ReadAll(res.Body)
			if err != nil {
				return nil, err
			}
			type Response struct {
				Status		string	`json:"status`
				Address		string	`json:"address"`
				PrivateKey	string	`json:"private_key"`
				Cert 		string	`json:"cert"`
				Id			int		`json:"vmid"`
			}
			var response Response
			err = json.Unmarshal(body, &response)
			if err != nil {
				return nil, err
			}
			if response.Status != "ok" {
				return nil, errors.New("Failed to auth")
			}
			if unixUsername == "recovery" || unixUsername == "console" {
				conn, err := net.Dial("tcp", config.RecoveryServer)
				if err == nil {
					data.HasSentPassword = true
					data.Password = []byte(fmt.Sprintf("%d %s", response.Id, config.Token))
					return conn, nil
				}
			}
			conn, err := net.Dial("tcp", response.Address)
			if err != nil {
				return nil, err
			}
			var signer ssh.Signer
			if response.PrivateKey != "" {
				signer, err = ssh.ParsePrivateKey([]byte(response.PrivateKey))
				if err != nil {
				return conn, nil
				}
				pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(response.Cert))
				if err != nil {
					return conn, nil
				}
				certSigner, err := ssh.NewCertSigner(pk.(*ssh.Certificate), signer)
				if err != nil {
					return conn, nil
				}
				data.CertSigner = certSigner
			}
			return conn, nil
		}, &ssh.AuthPipe{
			User: sshUser,

			PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey, data *ssh.AuthData) (ssh.AuthPipeType, ssh.AuthMethod, error) {
				if data.HasSentPassword {
					return ssh.AuthPipeTypeMap, ssh.Password(string(data.Password)), nil
				} else if data.CertSigner != nil {
					return ssh.AuthPipeTypeMap, ssh.PublicKeys(data.CertSigner), nil
				}
				return ssh.AuthPipeTypeDiscard, nil, nil
			},

			PasswordCallback: func(conn ssh.ConnMetadata, password []byte, data *ssh.AuthData) (ssh.AuthPipeType, ssh.AuthMethod, error) {
				if !data.HasCheckedPublicKey {
					return ssh.AuthPipeTypeDiscard, nil, errors.New("haven't checked public key")
				}
				return ssh.AuthPipeTypePassThrough, nil, nil
			},

			UpstreamHostKeyCallback: ssh.InsecureIgnoreHostKey(),

			PasswordBeforePublicKeyCallback: func(password []byte, data *ssh.AuthData) {
				data.HasSentPassword = true
				data.Password = password
			},

			InteractiveInstrution: "Please enter Vlab username & password and UNIX password.",

			InteractiveQuestions: interactiveQuestions,

			InteractiveEcho: interactiveEcho,
		}, nil
}

func udpLogger(msg []byte) {
	conn, err := net.Dial("udp", config.Logger)
	if err != nil {
		return
	}
	conn.Write(msg)
}

func (p *plugin) GetName() string {
	return "vlab"
}

func (p *plugin) GetOpts() interface{} {
	return &config
}

func (p *plugin) GetHandler() upstream.Handler {
	return findUpstreamFromAPI
}

func (p *plugin) GetLogger() func([]byte) {
	return udpLogger
}

func (p *plugin) CreatePipe(opt upstream.CreatePipeOption) error {
	return nil
}

func (p *plugin) ListPipe() ([]upstream.Pipe, error) {
	return nil, nil
}

func (p *plugin) RemovePipe(name string) error {
	return nil
}

func (p *plugin) Init(glogger *log.Logger) error {
	logger = glogger
	logger.Printf("upstream provider: vlab, API: ", config.API)
	return nil
}

func init() {
	upstream.Register("vlab", &plugin{})
}
