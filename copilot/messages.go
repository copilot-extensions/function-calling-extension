package copilot

import "github.com/invopop/jsonschema"

type ChatRequest struct {
	Messages []ChatMessage `json:"messages"`
}

type ChatMessage struct {
	Role          string              `json:"role"`
	Content       string              `json:"content"`
	Confirmations []*ChatConfirmation `json:"copilot_confirmations"`
	ToolCalls     []*ToolCall         `json:"tool_calls"`
}

type ToolCall struct {
	Function *ChatMessageFunctionCall `json:"function"`
}

type ChatMessageFunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type ChatConfirmation struct {
	State        string            `json:"state"`
	Confirmation *ConfirmationData `json:"confirmation"`
}

type ConfirmationData struct {
	Owner string `json:"owner"`
	Repo  string `json:"repo"`
	Title string `json:"title"`
	Body  string `json:"body"`
}

type ResponseConfirmation struct {
	Type         string            `json:"type"`
	Title        string            `json:"title"`
	Message      string            `json:"message"`
	Confirmation *ConfirmationData `json:"confirmation"`
}

type Model string

const (
	ModelGPT35 Model = "gpt-3.5-turbo"
	ModelGPT4  Model = "gpt-4"
)

type ChatCompletionsRequest struct {
	Messages []ChatMessage  `json:"messages"`
	Model    Model          `json:"model"`
	Tools    []FunctionTool `json:"tools"`
}

type FunctionTool struct {
	Type     string   `json:"type"`
	Function Function `json:"function"`
}

type Function struct {
	Name        string             `json:"name"`
	Description string             `json:"description,omitempty"`
	Parameters  *jsonschema.Schema `json:"parameters"`
}

type ChatCompletionsResponse struct {
	Choices []ChatChoice `json:"choices"`
}

type ChatChoice struct {
	Index   int         `json:"index"`
	Message ChatMessage `json:"message"`
}
