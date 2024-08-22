package agent

import (
	"encoding/json"
	"io"
)

// Copilot extensions must stream back chat responses. sseWriter wraps an
// io.Writer to help write sse formated data.
type sseWriter struct {
	w io.Writer
}

func NewSSEWriter(w io.Writer) *sseWriter {
	return &sseWriter{
		w: w,
	}
}

// writeSSEDone writes a [DONE] SSE message to the writer.
func (w *sseWriter) writeDone() {
	_, _ = w.w.Write([]byte("data: [DONE]\n\n"))
}

// writeSSEData writes a data SSE message to the writer.
func (w *sseWriter) writeData(v any) error {
	_, _ = w.w.Write([]byte("data: "))
	if err := json.NewEncoder(w.w).Encode(v); err != nil {
		return err
	}
	_, _ = w.w.Write([]byte("\n")) // Encode() adds one newline, so add only one more here.
	return nil
}

// writeSSEEvent writes a data SSE message to the writer.
func (w *sseWriter) writeEvent(name string) error {
	_, err := w.w.Write([]byte("event: " + name))
	if err != nil {
		return err
	}
	_, err = w.w.Write([]byte("\n"))
	if err != nil {
		return err
	}
	return nil
}

type sseResponse struct {
	Choices []sseResponseChoice `json:"choices"`
}

type sseResponseChoice struct {
	Index int                `json:"index"`
	Delta sseResponseMessage `json:"delta"`
}

type sseResponseMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
