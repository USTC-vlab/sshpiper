package vlab

import (
	"github.com/tg123/sshpiper/sshpiperd/upstream"
	"golang.org/x/crypto/ssh"
	"net"
	"net/http"
	"log"
	"errors"
	"bytes"
	"io/ioutil"
	"encoding/base64"
	"encoding/json"
)

var logger *log.Logger

type plugin struct {
}

func findUpstreamFromAPI(conn ssh.ConnMetadata, challengeContext ssh.AdditionalChallengeContext) (
	func (key ssh.PublicKey, data interface{}) (net.Conn, interface{}, error), *ssh.AuthPipe, error) {
	type Data struct {
		Password string
	}
	return func (key ssh.PublicKey, data interface{}) (net.Conn, interface{}, error) {
		pubkeyType := key.Type()
		pubkeyData := base64.StdEncoding.EncodeToString(key.Marshal())
		type Request struct {
			PublicKeyType string `json:"public_key_type"`
			PublicKeyData string `json:"public_key_data"`
		}
		request := Request {
			PublicKeyType: pubkeyType,
			PublicKeyData: pubkeyData,
		}
		jsonData, err := json.Marshal(request)
		if err != nil {
			return nil, data, err
		}
		res, err := http.Post(config.API, "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			return nil, data, err
		}
		defer res.Body.Close()
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, data, err
		}
		type Response struct {
			Status string `json:"status`
			Address string `json:"address"`
		}
		var response Response
		err = json.Unmarshal(body, &response)
		if err != nil {
			return nil, data, err
		}
		if response.Status != "ok" {
			return nil, data, errors.New("not authenticated")
		}
		conn, err := net.Dial("tcp", response.Address)
		if err != nil {
			return nil, data, err
		}
		return conn, data, nil
	}, &ssh.AuthPipe{
		User: conn.User(),

		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey, data interface{}) (ssh.AuthPipeType, ssh.AuthMethod, interface{}, error) {
			data_, ok := data.(Data)
			if !ok {
				return ssh.AuthPipeTypeDiscard, nil, data, nil
			}
			password := data_.Password
			return ssh.AuthPipeTypeMap, ssh.Password(password), data, nil
		},

		PasswordCallback: func(conn ssh.ConnMetadata, password []byte, data interface{}) (ssh.AuthPipeType, ssh.AuthMethod, interface{}, error) {
			return ssh.AuthPipeTypeDiscard, nil, Data {
				Password: string(password),
			}, nil
		},

		UpstreamHostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}, nil
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