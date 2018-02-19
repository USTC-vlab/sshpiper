package main

import (
	"os"
	"runtime"
	"text/template"
)

var version = "DEV"
var githash = "0000000000"

func showVersion() {
	versionTemplate := template.Must(template.New("ver").Parse(`
SSHPiper ver: {{.VER}} by Boshi Lian<farmer1992@gmail.com>
https://github.com/tg123/sshpiper

go runtime  : {{.GOVER}}
git hash    : {{.GITHASH}}

`[1:]))

	versionTemplate.Execute(os.Stdout, struct {
		VER     string
		GOVER   string
		GITHASH string
	}{
		VER:     version,
		GITHASH: githash,
		GOVER:   runtime.Version(),
	})
}
