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
	func (key ssh.PublicKey, data *ssh.AuthData) (net.Conn, error), *ssh.AuthPipe, error) {
	return func (key ssh.PublicKey, data *ssh.AuthData) (net.Conn, error) {
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
			Status string `json:"status`
			Address string `json:"address"`
		}
		var response Response
		err = json.Unmarshal(body, &response)
		if err != nil {
			return nil, err
		}
		if response.Status != "ok" {
			return nil, errors.New("not authenticated")
		}
		conn, err := net.Dial("tcp", response.Address)
		if err != nil {
			return nil, err
		}
		return conn, nil
	}, &ssh.AuthPipe{
		User: conn.User(),

		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey, data *ssh.AuthData) (ssh.AuthPipeType, ssh.AuthMethod, error) {
			return ssh.AuthPipeTypeDiscard, nil, nil
		},

		PasswordCallback: func(conn ssh.ConnMetadata, password []byte, data *ssh.AuthData) (ssh.AuthPipeType, ssh.AuthMethod, error) {
			if !data.HasCheckedPublicKey {
				return ssh.AuthPipeTypeDiscard, nil, errors.New("haven't checked public key")
			}
			return ssh.AuthPipeTypePassThrough, nil, nil
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