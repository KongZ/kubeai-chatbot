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

// Skill represents a named, reusable instruction set that augments agent behavior.
// Skills are loaded from markdown files with YAML frontmatter.
type Skill struct {
	// Name is the unique identifier for the skill.
	Name string `yaml:"name"`
	// Description explains what the skill does; surfaced to the LLM in the system prompt.
	Description string `yaml:"description"`
	// Triggers is a list of keywords that auto-activate this skill when found in user messages.
	Triggers []string `yaml:"triggers"`
	// Instructions is the markdown body of the skill file — the actual guidance for the LLM.
	Instructions string `yaml:"-"`
}
