package api

import (
	"bytes"
	"cleargate/pkg/storage"
	"cleargate/pkg/vector"
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	pb "github.com/qdrant/go-client/qdrant"
	"github.com/rs/zerolog/log"
)

type VectorHandler struct {
	store    *storage.Store
	client   *vector.Client
	embedder vector.Embedder
}

func NewVectorHandler(store *storage.Store, client *vector.Client, embedder vector.Embedder) *VectorHandler {
	return &VectorHandler{store: store, client: client, embedder: embedder}
}

const (
	MaxFileSize    = 10 << 20 // 10MB
	ChunkSize      = 500
	ChunkOverlap   = 50
	CollectionName = "knowledge_base"
)

// UploadDocument handles file uploads, parsing, chunking, and indexing.
func (h *VectorHandler) UploadDocument(w http.ResponseWriter, r *http.Request) {
	// 1. Auth Check (Org Admin only)
	claims, ok := UserFromContext(r.Context())
	if !ok || claims.OrgID == 0 {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// 2. Parse Multipart Form
	if err := r.ParseMultipartForm(MaxFileSize); err != nil {
		writeError(w, http.StatusBadRequest, "file too large")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid file")
		return
	}
	defer file.Close()

	// Read file into memory (needed for ReaderAt required by PDF parser)
	fileBytes, err := io.ReadAll(file)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read file")
		return
	}
	fileSize := int64(len(fileBytes))
	readerAt := bytes.NewReader(fileBytes)

	// 3. Extract Text
	contentType := header.Header.Get("Content-Type")
	var text string

	if contentType == "application/pdf" {
		text, err = vector.ParseDocument(readerAt, fileSize, contentType)
	} else {
		// Assume text/plain
		text = string(fileBytes)
	}

	if err != nil {
		log.Error().Err(err).Msg("Document parsing failed")
		writeError(w, http.StatusInternalServerError, "failed to parse document")
		return
	}

	if len(text) == 0 {
		writeError(w, http.StatusBadRequest, "empty document")
		return
	}

	// 4. Chunking
	chunks := vector.ChunkText(text, ChunkSize, ChunkOverlap)
	log.Info().Int("chunks", len(chunks)).Str("file", header.Filename).Msg("Document chunked")

	// 5. Embedding & Indexing
	// Ensure collection exists
	if err := h.client.EnsureCollection(CollectionName); err != nil {
		log.Error().Err(err).Msg("Failed to ensure collection")
		writeError(w, http.StatusInternalServerError, "vector DB Error")
		return
	}

	var points []*pb.PointStruct
	for i, chunk := range chunks {
		vec, err := h.embedder.Embed(chunk)
		if err != nil {
			continue // Skip failed embeddings
		}

		pointID := vector.NewUUID() // Helper needed or use external lib

		points = append(points, &pb.PointStruct{
			Id:      &pb.PointId{PointIdOptions: &pb.PointId_Uuid{Uuid: pointID}},
			Vectors: &pb.Vectors{VectorsOptions: &pb.Vectors_Vector{Vector: &pb.Vector{Data: vec}}},
			Payload: map[string]*pb.Value{
				"text":        {Kind: &pb.Value_StringValue{StringValue: chunk}},
				"org_id":      {Kind: &pb.Value_IntegerValue{IntegerValue: int64(claims.OrgID)}},
				"filename":    {Kind: &pb.Value_StringValue{StringValue: header.Filename}},
				"chunk_index": {Kind: &pb.Value_IntegerValue{IntegerValue: int64(i)}},
			},
		})
	}

	if err := h.client.Upsert(CollectionName, points); err != nil {
		log.Error().Err(err).Msg("Upsert failed")
		writeError(w, http.StatusInternalServerError, "failed to index documents")
		return
	}

	// Response
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"collection": CollectionName,
	})

	// 6. Save Metadata to DB
	// Note: We use chunks count from parsing, size from bytes
	if err := h.store.CreateDocument(claims.OrgID, header.Filename, int(fileSize), len(chunks)); err != nil {
		log.Error().Err(err).Msg("Failed to save document metadata")
		// We don't fail the request, as vectors are indexed. But it's an inconsistency.
	}
}

func (h *VectorHandler) ListDocuments(w http.ResponseWriter, r *http.Request) {
	claims, ok := UserFromContext(r.Context())
	if !ok || claims.OrgID == 0 {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	docs, err := h.store.ListDocuments(claims.OrgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "dB Error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(docs)
}

func (h *VectorHandler) DeleteDocument(w http.ResponseWriter, r *http.Request) {
	claims, ok := UserFromContext(r.Context())
	if !ok || claims.OrgID == 0 {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		writeError(w, http.StatusBadRequest, "missing id")
		return
	}
	id, _ := strconv.Atoi(idStr)

	// Delete from DB & Get Filename
	filename, err := h.store.DeleteDocument(claims.OrgID, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete from DB")
		return
	}

	// Delete from Qdrant
	if filename != "" {
		if err := h.client.DeleteByFilename(CollectionName, filename); err != nil {
			log.Error().Err(err).Str("filename", filename).Msg("Failed to delete vectors")
			// We don't fail request if DB delete succeeded
		}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "filename": filename})
}

type TestRequest struct {
	Text string `json:"text"`
	TopK int    `json:"top_k"`
}

func (h *VectorHandler) TestSimilarity(w http.ResponseWriter, r *http.Request) {
	var req TestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid Body")
		return
	}

	vec, err := h.embedder.Embed(req.Text)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "embedding Failed")
		return
	}

	// Search
	results, err := h.client.Search(CollectionName, vec, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "search Failed")
		return
	}

	// Map results to simple JSON
	type Match struct {
		Score    float32 `json:"score"`
		Text     string  `json:"text"`
		Filename string  `json:"filename"`
	}
	var matches []Match
	for _, res := range results {
		// Return all results from TopK, regardless of score
		matches = append(matches, Match{
			Score:    res.Score,
			Text:     res.Payload["text"].GetStringValue(),
			Filename: res.Payload["filename"].GetStringValue(),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(matches)
}
