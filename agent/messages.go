package agent

type chatRequest struct {
	Messages []chatMessage `json:"messages"`
}

type chatMessage struct {
	Role          string              `json:"role"`
	Content       string              `json:"content"`
	Confirmations []*chatConfirmation `json:"copilot_confirmations"`
	ToolCalls     []*toolCall         `json:"tool_calls"`
}

type toolCall struct {
	Function *chatMessageFunctionCall `json:"function"`
}

type chatMessageFunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type chatConfirmation struct {
	State        string            `json:"state"`
	Confirmation *confirmationData `json:"confirmation"`
}

type confirmationData struct {
	Owner string `json:"owner"`
	Repo  string `json:"repo"`
	Title string `json:"title"`
	Body  string `json:"body"`
}

type responseConfirmation struct {
	Type         string            `json:"type"`
	Title        string            `json:"title"`
	Message      string            `json:"message"`
	Confirmation *confirmationData `json:"confirmation"`
}
