package vlab

var (
	config = struct {
		API	string `long:"upstream-vlab-api" description:"Authentication API" ini-name:"upstream-vlab-api"`
		Logger string `long:"logger" description:"Log API" ini-name:"upstream-vlab-logger"`
	}{}
)