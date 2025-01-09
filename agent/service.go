package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"

	"github.com/copilot-extensions/function-calling-extension/copilot"
	"github.com/google/go-github/v57/github"
	"github.com/invopop/jsonschema"
	"github.com/wk8/go-ordered-map/v2"
)

var tools []copilot.FunctionTool

func init() {
	listProperties := orderedmap.New[string, *jsonschema.Schema]()
	listProperties.Set("repository_owner", &jsonschema.Schema{
		Type:        "string",
		Description: "The owner of the repository",
	})
	listProperties.Set("repository_name", &jsonschema.Schema{
		Type:        "string",
		Description: "The name of the repository",
	})

	createProperties := orderedmap.New[string, *jsonschema.Schema]()
	createProperties.Set("repository_owner", &jsonschema.Schema{
		Type:        "string",
		Description: "The owner of the repository",
	})
	createProperties.Set("repository_name", &jsonschema.Schema{
		Type:        "string",
		Description: "The name of the repository",
	})
	createProperties.Set("issue_title", &jsonschema.Schema{
		Type:        "string",
		Description: "The title of the issue being created",
	})
	createProperties.Set("issue_body", &jsonschema.Schema{
		Type:        "string",
		Description: "The content of the issue being created",
	})

	tools = []copilot.FunctionTool{
		{
			Type: "function",
			Function: copilot.Function{
				Name:        "list_issues",
				Description: "Fetch a list of issues from github.com for a given repository.  Users may specify the repository owner and the repository name separately, or they may specify it in the form {repository_owner}/{repository_name}, or in the form github.com/{repository_owner}/{repository_name}.",
				Parameters: &jsonschema.Schema{
					Type:       "object",
					Properties: listProperties,
					Required:   []string{"repository_owner", "repository_name"},
				},
			},
		},
		{
			Type: "function",
			Function: copilot.Function{
				Name:        "create_issue_dialog",
				Description: "Creates a confirmation dialog in which the user can interact with in order to create an issue on a github.com repository.  Only one dialog should be created for each issue/repository combination.  Users may specify the repository owner and the repository name separately, or they may specify it in the form {repository_owner}/{repository_name}, or in the form github.com/{repository_owner}/{repository_name}.",
				Parameters: &jsonschema.Schema{
					Type:       "object",
					Properties: createProperties,
					Required:   []string{"repository_owner", "repository_name", "issue_title", "issue_body"},
				},
			},
		},
	}
}

// Service provides endpoint for this agent to perform chat completions
type Service struct {
	pubKey *ecdsa.PublicKey
}

func NewService(pubKey *ecdsa.PublicKey) *Service {
	return &Service{
		pubKey: pubKey,
	}
}

func (s *Service) ChatCompletion(w http.ResponseWriter, r *http.Request) {
	sig := r.Header.Get("Github-Public-Key-Signature")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		fmt.Println(fmt.Errorf("failed to read request body: %w", err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Make sure the payload matches the signature. In this way, you can be sure
	// that an incoming request comes from github
	isValid, err := validPayload(body, sig, s.pubKey)
	if err != nil {
		fmt.Printf("failed to validate payload signature: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if !isValid {
		http.Error(w, "invalid payload signature", http.StatusUnauthorized)
		return
	}

	apiToken := r.Header.Get("X-GitHub-Token")
	integrationID := r.Header.Get("Copilot-Integration-Id")

	var req *copilot.ChatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		fmt.Printf("failed to unmarshal request: %v\n", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := generateCompletion(r.Context(), integrationID, apiToken, req, NewSSEWriter(w)); err != nil {
		fmt.Printf("failed to execute agent: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func generateCompletion(ctx context.Context, integrationID, apiToken string, req *copilot.ChatRequest, w *sseWriter) error {
	// If the user clicks a confirmation box, handle that, and ignore everything else.
	for _, conf := range req.Messages[len(req.Messages)-1].Confirmations {
		if conf.State != "accepted" {
			continue
		}

		err := createIssue(ctx, apiToken, conf.Confirmation.Owner, conf.Confirmation.Repo, conf.Confirmation.Title, conf.Confirmation.Body)
		if err != nil {
			return err
		}

		w.writeData(sseResponse{
			Choices: []sseResponseChoice{
				{
					Index: 0,
					Delta: sseResponseMessage{
						Role:    "assistant",
						Content: fmt.Sprintf("Created issue %s on repository %s/%s", conf.Confirmation.Title, conf.Confirmation.Owner, conf.Confirmation.Repo),
					},
				},
			},
		})

		return nil
	}

	var messages []copilot.ChatMessage
	var confs []copilot.ConfirmationData
	messages = append(messages, req.Messages...)

	// The LLM will call functions when it wants more information.  We loop here in
	// order to feed that information back into the LLM
	for i := 0; i < 5; i++ {

		chatReq := &copilot.ChatCompletionsRequest{
			Model:    copilot.ModelGPT35,
			Messages: messages,
		}

		// Only give the LLM tools if we're not on the last loop.  On the final
		// iteration, we want to force a chat completion out of the LLM
		if i < 4 {
			chatReq.Tools = tools
		}

		res, err := copilot.ChatCompletions(ctx, integrationID, apiToken, chatReq)
		if err != nil {
			return fmt.Errorf("failed to get chat completions stream: %w", err)
		}

		function := getFunctionCall(res)

		// If there's no function call, send the completion back to the client
		if function == nil {
			choices := make([]sseResponseChoice, len(res.Choices))
			for i, choice := range res.Choices {
				choices[i] = sseResponseChoice{
					Index: choice.Index,
					Delta: sseResponseMessage{
						Role:    choice.Message.Role,
						Content: choice.Message.Content,
					},
				}
			}

			w.writeData(sseResponse{
				Choices: choices,
			})
			w.writeDone()
			break
		}

		fmt.Println("found function!", function.Name)

		switch function.Name {

		case "list_issues":
			args := &struct {
				Owner string `json:"repository_owner"`
				Name  string `json:"repository_name"`
			}{}
			err := json.Unmarshal([]byte(function.Arguments), &args)
			if err != nil {
				return fmt.Errorf("error unmarshalling function arguments: %w", err)
			}
			msg, err := listIssues(ctx, apiToken, args.Owner, args.Name)
			if err != nil {
				return err
			}
			messages = append(messages, *msg)
		case "create_issue_dialog":
			args := &struct {
				Owner string `json:"repository_owner"`
				Name  string `json:"repository_name"`
				Title string `json:"issue_title"`
				Body  string `json:"issue_body"`
			}{}
			err := json.Unmarshal([]byte(function.Arguments), &args)
			if err != nil {
				return fmt.Errorf("error unmarshalling function arguments: %w", err)
			}

			conf, msg := createIssueConfirmation(args.Owner, args.Name, args.Title, args.Body)

			found := false
			for _, existing_conf := range confs {
				if *conf.Confirmation == existing_conf {
					found = true
					break
				}
			}

			if !found {
				confs = append(confs, *conf.Confirmation)

				if err := w.writeEvent("copilot_confirmation"); err != nil {
					return fmt.Errorf("failed to write event: %w", err)
				}

				if err := w.writeData(conf); err != nil {
					return fmt.Errorf("failed to write data: %w", err)
				}

				messages = append(messages, *msg)
			}
		default:
			return fmt.Errorf("unknown function call: %s", function.Name)
		}
	}
	return nil
}

func listIssues(ctx context.Context, apiToken, owner, repo string) (*copilot.ChatMessage, error) {
	client := github.NewClient(nil).WithAuthToken(apiToken)
	issues, _, err := client.Issues.ListByRepo(ctx, owner, repo, nil)
	if err != nil {
		return nil, fmt.Errorf("error fetching issues: %w", err)
	}

	serializedIssues, err := json.Marshal(issues)
	if err != nil {
		return nil, fmt.Errorf("error serializing issues")
	}

	return &copilot.ChatMessage{
		Role:    "system",
		Content: fmt.Sprintf("The issues for the repository %s/%s are: %s", owner, repo, string(serializedIssues)),
	}, nil
}

func createIssueConfirmation(owner, repo, title, body string) (*copilot.ResponseConfirmation, *copilot.ChatMessage) {
	return &copilot.ResponseConfirmation{
			Type:    "action",
			Title:   "Create Issue",
			Message: fmt.Sprintf("Are you sure you want to create an issue in repository %s/%s with the title \"%s\" and the content \"%s\"", owner, repo, title, body),
			Confirmation: &copilot.ConfirmationData{
				Owner: owner,
				Repo:  repo,
				Title: title,
				Body:  body,
			},
		}, &copilot.ChatMessage{
			Role:    "system",
			Content: fmt.Sprintf("Issue dialog created: {\"issue_title\": \"%s\", \"issue_body\": \"%s\", \"repository_owner\": \"%s\", \"repository_name\": \"%s\"}", title, body, owner, repo),
		}
}

func createIssue(ctx context.Context, apiToken, owner, repo, title, body string) error {
	client := github.NewClient(nil).WithAuthToken(apiToken)
	_, _, err := client.Issues.Create(ctx, owner, repo, &github.IssueRequest{
		Title: &title,
		Body:  &body,
	})
	if err != nil {
		return fmt.Errorf("error creating issue: %w", err)
	}

	return nil
}

// asn1Signature is a struct for ASN.1 serializing/parsing signatures.
type asn1Signature struct {
	R *big.Int
	S *big.Int
}

func validPayload(data []byte, sig string, publicKey *ecdsa.PublicKey) (bool, error) {
	asnSig, err := base64.StdEncoding.DecodeString(sig)
	parsedSig := asn1Signature{}
	if err != nil {
		return false, err
	}
	rest, err := asn1.Unmarshal(asnSig, &parsedSig)
	if err != nil || len(rest) != 0 {
		return false, err
	}

	// Verify the SHA256 encoded payload against the signature with GitHub's Key
	digest := sha256.Sum256(data)
	return ecdsa.Verify(publicKey, digest[:], parsedSig.R, parsedSig.S), nil
}

func getFunctionCall(res *copilot.ChatCompletionsResponse) *copilot.ChatMessageFunctionCall {
	if len(res.Choices) == 0 {
		return nil
	}

	if len(res.Choices[0].Message.ToolCalls) == 0 {
		return nil
	}

	funcCall := res.Choices[0].Message.ToolCalls[0].Function
	if funcCall == nil {
		return nil
	}
	return funcCall

}
