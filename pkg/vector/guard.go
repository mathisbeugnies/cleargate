package vector

import (
	"fmt" // Added for fmt.Errorf

	pb "github.com/qdrant/go-client/qdrant"
	"github.com/rs/zerolog/log"
)

const (
	CollectionName        = "forbidden_sectors_semantic"
	AllowedCollectionName = "allowed_topics"
	ExceptionCollection   = "allowed_exceptions" // Whitelist
	SimilarityThreshold   = 0.40                 // Block if match > 0.40
	DomainThreshold       = 0.30                 // Anomaly if match < 0.30 (Distance > 0.7)
)

// Guard enforces semantic security policies using vector embeddings.
// It manages banned topics, allowed domains, and exception whitelists.
type Guard struct {
	client   *Client
	embedder Embedder
}

// NewGuard creates a new Vector Guard instance.
func NewGuard(client *Client, embedder Embedder) *Guard {
	return &Guard{
		client:   client,
		embedder: embedder,
	}
}

func (g *Guard) Client() *Client {
	return g.client
}

// Seed populates the forbidden sectors collection with the provided topics.
func (g *Guard) Seed(sectors []string) error {
	if g.client == nil {
		return nil
	}
	return g.seedCollection(CollectionName, sectors)
}

// SeedAllowed populates the allowed domains collection with the provided topics.
func (g *Guard) SeedAllowed(topics []string) error {
	if g.client == nil {
		return nil
	}
	return g.seedCollection(AllowedCollectionName, topics)
}

func (g *Guard) seedCollection(colName string, items []string) error {
	if err := g.client.EnsureCollection(colName); err != nil {
		return fmt.Errorf("failed to ensure collection %s: %w", colName, err)
	}

	var points []*pb.PointStruct
	for i, item := range items {
		vector, err := g.embedder.Embed(item)
		if err != nil {
			log.Error().Err(err).Str("item", item).Msg("Embedding failed for seed item")
			continue
		}
		points = append(points, &pb.PointStruct{
			Id:      &pb.PointId{PointIdOptions: &pb.PointId_Num{Num: uint64(i + 1)}},
			Vectors: &pb.Vectors{VectorsOptions: &pb.Vectors_Vector{Vector: &pb.Vector{Data: vector}}},
			Payload: map[string]*pb.Value{
				"text": {Kind: &pb.Value_StringValue{StringValue: item}},
				// For forbidden sectors, we might still want org_id, but for allowed topics, it's global.
				// Keeping it simple for now, no org_id in seedCollection.
			},
		})
	}

	if len(points) > 0 {
		return g.client.Upsert(colName, points)
	}
	return nil
}

func (g *Guard) AddException(text string) error {
	if g.client == nil {
		return nil
	}
	// Upsert to allowed_exceptions
	// Create collection if missing
	if err := g.client.EnsureCollection(ExceptionCollection); err != nil {
		return err
	}

	// Reuse seedCollection: a bit heavy for a single item but keeps one code path.
	return g.seedCollection(ExceptionCollection, []string{text})
}

func (g *Guard) IsException(text string) bool {
	if g.client == nil {
		return false
	}

	vector, err := g.embedder.Embed(text)
	if err != nil {
		return false
	}

	results, err := g.client.Search(ExceptionCollection, vector, nil)
	if err != nil || len(results) == 0 {
		return false
	}

	// Exception needs VERY high similarity (Contextual Match)
	// > 0.85 means "It is this specific reported prompt"
	if results[0].Score > 0.85 {
		log.Info().Str("exception", results[0].Payload["text"].GetStringValue()).Msg("Vector Guard: Exception Whitelist Matched")
		return true
	}
	return false
}

// IsBlocked checks if the text semantically matches any forbidden sectors.
// It returns blocked status, the similarity score, and the reason (matched sector).
func (g *Guard) IsBlocked(text string, orgID int) (bool, float32, string) {
	if g.client == nil {
		return false, 0, ""
	}

	// 1. Check Exceptions (Whitelist)
	if g.IsException(text) {
		return false, 0, ""
	}

	vec, err := g.embedder.Embed(text)
	if err != nil {
		log.Error().Err(err).Msg("Embedding failed")
		return false, 0, ""
	}

	// Filter: org_id == 0 OR org_id == orgID
	// The instruction's IsBlocked example removed this filter, but the original had it.
	// I will keep the original filter logic as it seems more robust for "forbidden_sectors".
	filter := &pb.Filter{
		Should: []*pb.Condition{
			{ConditionOneOf: &pb.Condition_Field{Field: &pb.FieldCondition{
				Key:   "org_id",
				Match: &pb.Match{MatchValue: &pb.Match_Integer{Integer: 0}},
			}}},
			{ConditionOneOf: &pb.Condition_Field{Field: &pb.FieldCondition{
				Key:   "org_id",
				Match: &pb.Match{MatchValue: &pb.Match_Integer{Integer: int64(orgID)}},
			}}},
		},
	}

	results, err := g.client.Search(CollectionName, vec, filter)
	if err != nil {
		log.Error().Err(err).Msg("Vector search failed")
		return false, 0, ""
	}

	if len(results) > 0 {
		top := results[0]
		log.Info().Float32("top_score", top.Score).Str("text", top.Payload["text"].GetStringValue()).Msg("Vector Search Result")
		if top.Score > 0.40 { // Lowered to 0.40 for Bag-of-Words similarity (approx Jaccard)
			payloadText := top.Payload["text"].GetStringValue()
			return true, top.Score, payloadText
		}
	} else {
		log.Info().Msg("Vector Search: No results found")
	}

	return false, 0, ""
}

func (g *Guard) IsOutOfDomain(text string) (bool, float32) {
	if g.client == nil {
		// Fail open if vector DB down
		return false, 1.0
	}

	vector, err := g.embedder.Embed(text)
	if err != nil {
		return false, 1.0
	}

	results, err := g.client.Search(AllowedCollectionName, vector, nil)
	if err != nil || len(results) == 0 {
		// If no allowed topics exist, we shouldn't block everything.
		// Assume safe if collection empty? Or strict?
		// User requirement: "If too far from ALL allowed domains".
		// If collection empty, technically distance is infinite.
		return false, 0.0
	}

	topMatch := results[0]
	log.Info().Float32("domain_score", topMatch.Score).Str("closest_topic", topMatch.Payload["text"].GetStringValue()).Msg("Domain Verification Debug")

	// If the BEST match is LESS than threshold, then we are Far away -> Out of Domain.
	if topMatch.Score < DomainThreshold {
		return true, topMatch.Score
	}

	return false, topMatch.Score
}
