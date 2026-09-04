package main

import (
	"context"
	"fmt"
	"log"
	"time"

	pb "github.com/qdrant/go-client/qdrant"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	addr := "localhost:6334"
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Did not connect: %v", err)
	}
	defer conn.Close()

	colClient := pb.NewCollectionsClient(conn)
	pointsClient := pb.NewPointsClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// List Collections
	cols, err := colClient.List(ctx, &pb.ListCollectionsRequest{})
	if err != nil {
		log.Fatalf("Failed to list collections: %v", err)
	}

	fmt.Println("Collections:")
	for _, c := range cols.Collections {
		fmt.Printf("- %s\n", c.Name)
	}

	// Count Allowed
	count, err := pointsClient.Count(ctx, &pb.CountPoints{
		CollectionName: "allowed_topics",
	})
	if err != nil {
		fmt.Printf("Error counting allowed_topics (might not exist): %v\n", err)
	} else {
		fmt.Printf("Count 'allowed_topics': %d\n", count.Result.Count)
	}
}
