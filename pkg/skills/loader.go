// Copyright 2026 https://github.com/KongZ/kubeai-chatbot
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package skills

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadFromDir reads all .md skill files from dir and returns the parsed skills.
// Returns nil (no error) if the directory does not exist.
func LoadFromDir(dir string) ([]Skill, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading skills directory %s: %w", dir, err)
	}

	var result []Skill
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".md") {
			continue
		}
		skill, err := loadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("loading skill %s: %w", entry.Name(), err)
		}
		if skill.Name == "" {
			continue // skip files without a name
		}
		result = append(result, skill)
	}
	return result, nil
}

func loadFile(path string) (Skill, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return Skill{}, err
	}
	fm, body, err := parseFrontmatter(content)
	if err != nil {
		return Skill{}, fmt.Errorf("parsing frontmatter: %w", err)
	}
	var skill Skill
	if len(fm) > 0 {
		if err := yaml.Unmarshal(fm, &skill); err != nil {
			return Skill{}, fmt.Errorf("parsing YAML frontmatter: %w", err)
		}
	}
	skill.Instructions = strings.TrimSpace(body)
	return skill, nil
}

// parseFrontmatter splits markdown content into YAML frontmatter bytes and body text.
// Frontmatter must be delimited by leading and closing "---" lines.
func parseFrontmatter(content []byte) (frontmatter []byte, body string, err error) {
	scanner := bufio.NewScanner(bytes.NewReader(content))
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if len(lines) == 0 || lines[0] != "---" {
		return nil, string(content), nil
	}

	end := -1
	for i := 1; i < len(lines); i++ {
		if lines[i] == "---" {
			end = i
			break
		}
	}
	if end == -1 {
		return nil, string(content), nil
	}

	fm := strings.Join(lines[1:end], "\n")
	bodyStr := strings.Join(lines[end+1:], "\n")
	return []byte(fm), bodyStr, nil
}
