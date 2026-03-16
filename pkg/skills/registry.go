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
	"strings"
	"sync"
)

// Registry holds loaded skills and supports lookup by keyword matching.
type Registry struct {
	mu     sync.RWMutex
	skills []Skill
}

// Register adds a skill to the registry.
func (r *Registry) Register(skill Skill) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.skills = append(r.skills, skill)
}

// All returns a copy of all registered skills.
func (r *Registry) All() []Skill {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Skill, len(r.skills))
	copy(result, r.skills)
	return result
}

// Match returns skills whose trigger keywords appear in message (case-insensitive).
// Each skill is returned at most once even if multiple triggers match.
func (r *Registry) Match(message string) []Skill {
	r.mu.RLock()
	defer r.mu.RUnlock()
	lower := strings.ToLower(message)
	var matched []Skill
	for _, s := range r.skills {
		for _, trigger := range s.Triggers {
			if strings.Contains(lower, strings.ToLower(trigger)) {
				matched = append(matched, s)
				break
			}
		}
	}
	return matched
}
