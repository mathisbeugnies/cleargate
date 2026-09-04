package vector

import (
	"context"
	"time"

	pb "github.com/qdrant/go-client/qdrant"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Client struct {
	conn   *grpc.ClientConn
	points pb.PointsClient
	col    pb.CollectionsClient
}

func NewClient(addr string) (*Client, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	return &Client{
		conn:   conn,
		points: pb.NewPointsClient(conn),
		col:    pb.NewCollectionsClient(conn),
	}, nil
}

func (c *Client) EnsureCollection(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check if exists
	_, err := c.col.Get(ctx, &pb.GetCollectionInfoRequest{CollectionName: name})
	if err == nil {
		return nil // Exists
	}

	// Create
	_, err = c.col.Create(ctx, &pb.CreateCollection{
		CollectionName: name,
		VectorsConfig: &pb.VectorsConfig{Config: &pb.VectorsConfig_Params{
			Params: &pb.VectorParams{
				Size:     384,
				Distance: pb.Distance_Cosine,
			},
		}},
	})
	return err
}

func (c *Client) Upsert(collectionName string, points []*pb.PointStruct) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := c.points.Upsert(ctx, &pb.UpsertPoints{
		CollectionName: collectionName,
		Points:         points,
	})
	return err
}

func (c *Client) Search(collectionName string, vector []float32, filter *pb.Filter) ([]*pb.ScoredPoint, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := c.points.Search(ctx, &pb.SearchPoints{
		CollectionName: collectionName,
		Vector:         vector,
		Limit:          1,
		WithPayload:    &pb.WithPayloadSelector{SelectorOptions: &pb.WithPayloadSelector_Enable{Enable: true}},
		Filter:         filter,
	})
	if err != nil {
		return nil, err
	}
	return resp.Result, nil
}

func (c *Client) DeleteByFilename(collectionName string, filename string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := c.points.Delete(ctx, &pb.DeletePoints{
		CollectionName: collectionName,
		Points: &pb.PointsSelector{
			PointsSelectorOneOf: &pb.PointsSelector_Filter{
				Filter: &pb.Filter{
					Must: []*pb.Condition{
						{ConditionOneOf: &pb.Condition_Field{Field: &pb.FieldCondition{
							Key:   "filename",
							Match: &pb.Match{MatchValue: &pb.Match_Keyword{Keyword: filename}},
						}}},
					},
				},
			},
		},
	})
	return err
}

func (c *Client) GetCollectionInfo(name string) (uint64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	info, err := c.col.Get(ctx, &pb.GetCollectionInfoRequest{CollectionName: name})
	if err != nil {
		return 0, err
	}
	// PointsCount is an optional proto field and may be nil.
	if info.GetResult() == nil || info.GetResult().PointsCount == nil {
		return 0, nil
	}
	return *info.GetResult().PointsCount, nil
}
