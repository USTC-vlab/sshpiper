package vlab

import (
	"github.com/tg123/sshpiper/sshpiperd/upstream"
	"golang.org/x/crypto/ssh"
	"net"
	"net/http"
	"log"
	"bytes"
	"io/ioutil"
	"encoding/base64"
	"encoding/json"
)

var logger *log.Logger

type plugin struct {
}

func findUpstreamFromAPI(conn ssh.ConnMetadata, challengeContext ssh.AdditionalChallengeContext) (
	func (key ssh.PublicKey) (conn net.Conn, data interface{}, err error), *ssh.AuthPipe, error) {
	return func (key ssh.PublicKey) (conn net.Conn, data interface{}, err error) {
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
			return nil, nil, err
		}
		res, err := http.Post(config.API, "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			return nil, nil, err
		}
		defer res.Body.Close()
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, nil, err
		}
		type Response struct {
			Address string `json:"address"`
			PrivateKey string `json:"private_key"`
		}
		var response Response
		err = json.Unmarshal(body, &response)
		if err != nil {
			return nil, nil, err
		}
		signer, err := ssh.ParsePrivateKey([]byte(response.PrivateKey))
		if err != nil || signer == nil {
			return nil, nil, err
		}
		conn, err = net.Dial("tcp", response.Address)
		if err != nil {
			return nil, nil, err
		}
		return conn, signer, nil
	}, &ssh.AuthPipe{
		User: conn.User(),

		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey, data interface{}) (ssh.AuthPipeType, ssh.AuthMethod, error) {
			signer, ok := data.(ssh.Signer)
			if !ok || signer == nil {
				// try one
				return ssh.AuthPipeTypeNone, nil, nil
			}
 
			return ssh.AuthPipeTypeMap, ssh.PublicKeys(signer), nil
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