package main

// Test AWS SDK with custom CA bundle to see if it works with the
// AWS_CONTAINER_CREDENTIALS_FULL_URI environment variable set.

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func main() {
	ca, err := os.Open("./CA.crt")
	if err != nil {
		panic(fmt.Sprintf("Unable to open CA.crt: %v", err))
	}
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithCustomCABundle(ca))
	if err != nil {
		panic(err)
	}

	client := sts.NewFromConfig(cfg)
	output, err := client.GetCallerIdentity(context.TODO(), nil)
	if err != nil {
		panic(err)
	}
	fmt.Printf("identity: %v\n", output)
}
