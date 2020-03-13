package vlab

import (
	"github.com/tg123/sshpiper/sshpiperd/upstream"
	"golang.org/x/crypto/ssh"
	"net"
	"log"
	"io/ioutil"
)

var logger *log.Logger

type plugin struct {
}

func findUpstreamFromAPI(conn ssh.ConnMetadata, challengeContext ssh.AdditionalChallengeContext) (
	func (key ssh.PublicKey) (conn net.Conn), *ssh.AuthPipe, error) {
	return func (key ssh.PublicKey) (conn net.Conn) {
		conn, err := net.Dial("tcp", "13.114.30.148:22")
		if err != nil {
			return nil
		}
		return conn
	}, &ssh.AuthPipe{
		User: conn.User(),

		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (ssh.AuthPipeType, ssh.AuthMethod, error) {
			pk, err := ioutil.ReadFile("/Users/pengdinglan/pdl-tokyo.pem")
			signer, err := ssh.ParsePrivateKey(pk)
			if err != nil || signer == nil {
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