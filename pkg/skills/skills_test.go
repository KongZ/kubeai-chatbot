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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- parseFrontmatter ---

func TestParseFrontmatter_Valid(t *testing.T) {
	content := []byte("---\nname: test\ndescription: a test skill\n---\n\nInstructions go here.")
	fm, body, err := parseFrontmatter(content)
	require.NoError(t, err)
	assert.Equal(t, "name: test\ndescription: a test skill", string(fm))
	assert.Contains(t, body, "Instructions go here.")
}

func TestParseFrontmatter_NoFrontmatter(t *testing.T) {
	content := []byte("Just a plain markdown file.")
	fm, body, err := parseFrontmatter(content)
	require.NoError(t, err)
	assert.Empty(t, fm)
	assert.Equal(t, "Just a plain markdown file.", body)
}

func TestParseFrontmatter_UnclosedDelimiter(t *testing.T) {
	content := []byte("---\nname: test\n\nNo closing delimiter.")
	fm, body, err := parseFrontmatter(content)
	require.NoError(t, err)
	assert.Empty(t, fm) // treated as no frontmatter
	assert.Equal(t, string(content), body)
}

func TestParseFrontmatter_EmptyBody(t *testing.T) {
	content := []byte("---\nname: test\n---\n")
	fm, body, err := parseFrontmatter(content)
	require.NoError(t, err)
	assert.Equal(t, "name: test", string(fm))
	assert.Empty(t, body)
}

// --- LoadFromDir ---

func writeSkillFile(t *testing.T, dir, name, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644))
}

func TestLoadFromDir_MissingDir(t *testing.T) {
	skills, err := LoadFromDir("/nonexistent/path/to/skills")
	require.NoError(t, err)
	assert.Nil(t, skills)
}

func TestLoadFromDir_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	skills, err := LoadFromDir(dir)
	require.NoError(t, err)
	assert.Empty(t, skills)
}

func TestLoadFromDir_SkipsNonMdFiles(t *testing.T) {
	dir := t.TempDir()
	writeSkillFile(t, dir, "skill.txt", "---\nname: txt-skill\n---\nBody.")
	writeSkillFile(t, dir, "skill.yaml", "name: yaml-skill")
	skills, err := LoadFromDir(dir)
	require.NoError(t, err)
	assert.Empty(t, skills)
}

func TestLoadFromDir_SkipsFilesWithoutName(t *testing.T) {
	dir := t.TempDir()
	writeSkillFile(t, dir, "unnamed.md", "---\ndescription: no name here\n---\nBody.")
	skills, err := LoadFromDir(dir)
	require.NoError(t, err)
	assert.Empty(t, skills)
}

func TestLoadFromDir_SingleSkill(t *testing.T) {
	dir := t.TempDir()
	writeSkillFile(t, dir, "debug-crashloop.md", `---
name: debug-crashloop
description: Debug a CrashLoopBackOff pod
triggers:
  - crashloop
  - CrashLoopBackOff
---

Step 1: kubectl describe pod
Step 2: kubectl logs --previous`)

	loaded, err := LoadFromDir(dir)
	require.NoError(t, err)
	require.Len(t, loaded, 1)

	s := loaded[0]
	assert.Equal(t, "debug-crashloop", s.Name)
	assert.Equal(t, "Debug a CrashLoopBackOff pod", s.Description)
	assert.Equal(t, []string{"crashloop", "CrashLoopBackOff"}, s.Triggers)
	assert.Contains(t, s.Instructions, "kubectl describe pod")
	assert.Contains(t, s.Instructions, "kubectl logs --previous")
}

func TestLoadFromDir_MultipleSkills(t *testing.T) {
	dir := t.TempDir()
	writeSkillFile(t, dir, "skill-a.md", "---\nname: skill-a\n---\nInstructions A.")
	writeSkillFile(t, dir, "skill-b.md", "---\nname: skill-b\n---\nInstructions B.")

	loaded, err := LoadFromDir(dir)
	require.NoError(t, err)
	assert.Len(t, loaded, 2)

	names := []string{loaded[0].Name, loaded[1].Name}
	assert.Contains(t, names, "skill-a")
	assert.Contains(t, names, "skill-b")
}

func TestLoadFromDir_LoadsSubdirectories(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "custom")
	require.NoError(t, os.Mkdir(subdir, 0o755))
	writeSkillFile(t, subdir, "nested.md", "---\nname: nested\n---\nBody.")

	loaded, err := LoadFromDir(dir)
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	assert.Equal(t, "nested", loaded[0].Name)
}

func TestLoadFromDir_SkipsDeepSubdirectories(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "custom")
	deepdir := filepath.Join(subdir, "deep")
	require.NoError(t, os.MkdirAll(deepdir, 0o755))
	writeSkillFile(t, deepdir, "deep.md", "---\nname: deep\n---\nBody.")

	loaded, err := LoadFromDir(dir)
	require.NoError(t, err)
	assert.Empty(t, loaded)
}

func TestLoadFromDir_InstructionsTrimmed(t *testing.T) {
	dir := t.TempDir()
	writeSkillFile(t, dir, "trim.md", "---\nname: trim\n---\n\n\n  Instructions with whitespace.  \n\n")

	loaded, err := LoadFromDir(dir)
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	assert.Equal(t, "Instructions with whitespace.", loaded[0].Instructions)
}

// --- Registry ---

func TestRegistry_AllEmpty(t *testing.T) {
	r := &Registry{}
	assert.Empty(t, r.All())
}

func TestRegistry_RegisterAndAll(t *testing.T) {
	r := &Registry{}
	r.Register(Skill{Name: "skill-a", Description: "A"})
	r.Register(Skill{Name: "skill-b", Description: "B"})

	all := r.All()
	assert.Len(t, all, 2)
	assert.Equal(t, "skill-a", all[0].Name)
	assert.Equal(t, "skill-b", all[1].Name)
}

func TestRegistry_AllReturnsCopy(t *testing.T) {
	r := &Registry{}
	r.Register(Skill{Name: "skill-a"})

	all := r.All()
	all[0].Name = "mutated"

	// original must be unchanged
	assert.Equal(t, "skill-a", r.All()[0].Name)
}

func TestRegistry_MatchNoTriggers(t *testing.T) {
	r := &Registry{}
	r.Register(Skill{Name: "no-triggers"})
	assert.Empty(t, r.Match("any message"))
}

func TestRegistry_MatchExact(t *testing.T) {
	r := &Registry{}
	r.Register(Skill{Name: "crashloop", Triggers: []string{"CrashLoopBackOff"}})
	matched := r.Match("my pod is in CrashLoopBackOff state")
	require.Len(t, matched, 1)
	assert.Equal(t, "crashloop", matched[0].Name)
}

func TestRegistry_MatchCaseInsensitive(t *testing.T) {
	r := &Registry{}
	r.Register(Skill{Name: "crashloop", Triggers: []string{"crashloopbackoff"}})
	matched := r.Match("pod stuck in CrashLoopBackOff")
	require.Len(t, matched, 1)
	assert.Equal(t, "crashloop", matched[0].Name)
}

func TestRegistry_MatchMultipleTriggers_ReturnsOnce(t *testing.T) {
	r := &Registry{}
	r.Register(Skill{Name: "crashloop", Triggers: []string{"crashloop", "CrashLoopBackOff"}})
	// Both triggers appear in the message but the skill should only be returned once
	matched := r.Match("pod crashloop CrashLoopBackOff issue")
	assert.Len(t, matched, 1)
}

func TestRegistry_MatchMultipleSkills(t *testing.T) {
	r := &Registry{}
	r.Register(Skill{Name: "crashloop", Triggers: []string{"crashloop"}})
	r.Register(Skill{Name: "oom", Triggers: []string{"OOMKilled"}})
	r.Register(Skill{Name: "rbac", Triggers: []string{"forbidden"}})

	matched := r.Match("pod is OOMKilled and also forbidden to access resource")
	assert.Len(t, matched, 2)
	names := []string{matched[0].Name, matched[1].Name}
	assert.Contains(t, names, "oom")
	assert.Contains(t, names, "rbac")
}

func TestRegistry_MatchNoMatch(t *testing.T) {
	r := &Registry{}
	r.Register(Skill{Name: "crashloop", Triggers: []string{"crashloop"}})
	assert.Empty(t, r.Match("everything is fine today"))
}

