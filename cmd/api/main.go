package main

import (
	"log"

	"github.com/vultisig/vultiserver/api"
	"github.com/vultisig/vultiserver/storage"
)

// @title Vultiserver API
// @version 1.0
// @description Vultisig server API for vault management and cryptographic operations
// @host localhost:8080
// @BasePath /
// @securityDefinitions.apikey XPassword
// @in header
// @name x-password
func main() {
	// Initialize your dependencies here
	// This is a simplified example - adapt to your actual initialization
	redis := &storage.RedisStorage{}
	
	server := api.NewServer(
		8080,
		redis,
		nil, // asynq client
		nil, // asynq inspector
		"",  // vault file path
		nil, // statsd client
		nil, // block storage
	)
	
	if err := server.StartServer(); err != nil {
		log.Fatal(err)
	}
}