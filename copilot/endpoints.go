package copilot

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func ChatCompletions(ctx context.Context, integrationID, apiKey string, req *ChatCompletionsRequest) (*ChatCompletionsResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.githubcopilot.com/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	if integrationID != "" {
		httpReq.Header.Set("Copilot-Integration-Id", integrationID)
	}

	resp, err := (&http.Client{}).Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		fmt.Println(string(b))
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var chatRes *ChatCompletionsResponse
	err = json.NewDecoder(resp.Body).Decode(&chatRes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	return chatRes, nil
}
