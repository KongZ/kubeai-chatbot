package slack

import (
	"github.com/slack-go/slack"
)

// TableBlock represents the new Slack Table Block
// See: https://docs.slack.dev/reference/block-kit/blocks/table-block/
type TableBlock struct {
	TypeVal        string         `json:"type"`
	ColumnSettings []TableColumn  `json:"column_settings,omitempty"`
	Rows           [][]*TableCell `json:"rows"`
	BlockIDVal     string         `json:"block_id,omitempty"`
}

func (s TableBlock) BlockType() slack.MessageBlockType {
	return slack.MessageBlockType(s.TypeVal)
}

func (s TableBlock) BlockID() string {
	return s.BlockIDVal
}

func (s TableBlock) ID() string {
	return s.BlockIDVal
}

type TableColumn struct {
	Align     string `json:"align,omitempty"`      // left, center, right
	IsWrapped bool   `json:"is_wrapped,omitempty"` // Default: false
}

type TableCell struct {
	Type string `json:"type"` // "raw_text"
	Text string `json:"text"`
}

// NewTableBlock creates a new TableBlock following the correct Slack schema.
// Returns nil if the table exceeds Slack's limits or is invalid.
func NewTableBlock(headers []string, rows [][]string) *TableBlock {
	// Slack table limits (as of 2024):
	// - Maximum 5 columns
	// - Maximum 50 rows (including header)
	if len(headers) == 0 || len(headers) > 5 {
		return nil
	}
	if len(rows) > 49 { // 49 data rows + 1 header = 50 total
		return nil
	}

	tb := &TableBlock{
		TypeVal: "table",
	}

	// Initialize column settings
	for range headers {
		tb.ColumnSettings = append(tb.ColumnSettings, TableColumn{
			Align:     "left",
			IsWrapped: true,
		})
	}

	// Slack TableBlock rows include headers as the first row
	allRows := [][]string{headers}
	allRows = append(allRows, rows...)

	for _, rowData := range allRows {
		var row []*TableCell
		for i, cellData := range rowData {
			if i >= len(tb.ColumnSettings) {
				break
			}
			// Slack Table cells cannot be empty
			if cellData == "" {
				cellData = "\u00A0" // Non-breaking space
			}
			// Truncate very long cell content
			if len(cellData) > 500 {
				cellData = cellData[:497] + "..."
			}
			row = append(row, &TableCell{
				Type: "raw_text",
				Text: cellData,
			})
		}
		// Pad with empty cells if row is short
		for i := len(row); i < len(tb.ColumnSettings); i++ {
			row = append(row, &TableCell{
				Type: "raw_text",
				Text: "\u00A0",
			})
		}
		tb.Rows = append(tb.Rows, row)
	}

	return tb
}
