package vlab

var (
	config = struct {
		API	string `long:"upstream-vlab-api" description:"Authentication API" ini-name:"upstream-vlab-api"`
		Logger string `long:"upstream-vlab-logger" description:"Log API" ini-name:"upstream-vlab-logger"`
		Token string `long:"upstream-vlab-token" description:"Auth API Token" ini-name:"upstream-vlab-token"`
	}{}
)