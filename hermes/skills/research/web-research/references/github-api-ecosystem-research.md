# GitHub API Ecosystem Research — Query Templates & Patterns

Quick-reference query templates for discovering tools, skills, plugins, and developer resources via the GitHub REST API.

## Common Query Patterns

### 1. Core ecosystem search (broad)

```bash
curl -s "https://api.github.com/search/repositories?q=KEYWORD1+KEYWORD2&sort=stars&order=desc&per_page=30" | python -c "
import json,sys
data = json.load(sys.stdin)
print(f'Total: {data[\"total_count\"]} repos')
for r in data.get('items', [])[:30]:
    print(f\"★{r['stargazers_count']:>6} | {r['full_name']:40} | {r.get('description','')[:100]}\")
"
```

### 2. Topic-filtered (more precise)

GitHub topics are more reliable than full-text — they're curated by maintainers:

```bash
# Repos with specific topics
curl -s "https://api.github.com/search/repositories?q=topic:CLAUDE.md+topic:skills&sort=stars&order=desc&per_page=15"
```

### 3. Language-filtered

```bash
# Only JavaScript/TypeScript tools
curl -s "https://api.github.com/search/repositories?q=claude+code+plugin&language:javascript+language:typescript&sort=stars"
```

### 4. Recent-only (last 3 months)

```bash
curl -s "https://api.github.com/search/repositories?q=claude+code+skills+pushed:>2026-04-01&sort=stars"
```

### 5. Awesome-list discovery

```
query: "awesome" + TOOL_NAME + "list"   → "awesome+claude+code+list"
query: "awesome" + TOOL_NAME + "skills" → "awesome+claude+skills"
```

### 6. GitHub topic pages (not API, but good for manual review)

Use the browser for:
```
https://github.com/topics/claude-code
https://github.com/topics/claude-skills
https://github.com/topics/claude-md
```

## Evaluating Results

| Criteria | What to check |
|----------|---------------|
| Stars vs forks ratio | High stars/low forks = popular read, low collaborative need |
| Pushed date | `pushed_at` field — stale? |
| Topics | If the repo tags itself with relevant topics, it's intentional |
| README substance | Is it a real tool or just a prompt collection? |
| License | MIT = easy to use, Apache-2.0 = safe for commercial, GPL/AGPL = copyleft |
| File count (`size` field) | Size in KB — tiny repos may be minimal; huge ones may have docs, examples, scripts |

## Reading Plugin Directories

For repos that organize plugins as subdirs (e.g. `anthropics/claude-code/plugins/`, `obra/superpowers/skills/`):

```bash
# 1. List plugin directories
curl -s "https://api.github.com/repos/OWNER/REPO/contents/plugins" | python -c "
import json,sys
for item in json.load(sys.stdin):
    if item['type'] == 'dir':
        print(item['name'])
"

# 2. Get each plugin's README (batch)
for p in plugin1 plugin2 plugin3; do
  echo "=== $p ==="
  curl -s "https://api.github.com/repos/OWNER/REPO/contents/plugins/$p/README.md" \
    -H "Accept: application/vnd.github.raw" | head -3
  echo ""
done
```

## Windows-specific Notes

- Use `python` (not `python3`) — on MSYS/git-bash, `python3` resolves to the Microsoft Store stub
- The GitHub API works fine via `curl` built into git-bash
- Pipe JSON through `python -c "import json,sys; ..."` for structured output — avoid shell-based JSON parsers like `jq` which may not be installed
- Use `2>/dev/null` to suppress curl's progress meter when piping

## Pitfalls

1. **Rate limiting.** Unauthenticated GitHub API: 60 requests/hour. If doing many queries, space them out. Authenticated: 5,000/hour — set `GITHUB_TOKEN` env var and use `-H "Authorization: token $GITHUB_TOKEN"` for heavy research.
2. **Truncated results.** If `incomplete_results: true`, the result set is too large. Add more specific query terms to narrow focus.
3. **README fetch failure.** Some repos don't have a README, or have it at a non-standard path. Fall back to checking `contents_url` for files.
4. **Empty description fields.** Many repos have no description. Cross-reference with their README content.
5. **Stale awesome lists.** An awesome list with 10K stars but unmaintained for 2 years will point to dead tools. Check the last commit date.
