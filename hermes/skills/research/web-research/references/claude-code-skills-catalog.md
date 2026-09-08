# Claude Code Skills Catalog — UI/UX & Product Development

Snapshot from July 2026 of the most notable Claude Code skills, plugins, and resources for building and shipping products with good UI/UX.

## Official Anthropic Plugins (shipped with Claude Code)

Source: `github.com/anthropics/claude-code/plugins/`

| Plugin | Purpose |
|--------|---------|
| **frontend-design** | Generates distinctive, production-grade frontend — anti-slop rules, typography, color systems |
| **feature-dev** | Structured feature dev workflow: codebase exploration → architecture → quality review |
| **code-review** | Automated PR review with confidence-based false-positive filtering |
| **pr-review-toolkit** | 6 specialized review agents: comments, test coverage, error handling, types, quality, simplification |
| **security-guidance** | 3-layer security review for generated code |
| **commit-commands** | Streamlined git workflow (commit, push, PR) |
| **hookify** | Create custom hooks to prevent unwanted behaviors |
| **ralph-wiggum** | Iterative self-referential AI development loops |
| **agent-sdk-dev** | Build Agent SDK apps (Python + TypeScript) |
| **plugin-dev** | Build Claude Code plugins (hooks, MCP, marketplace publishing) |
| **explanatory-output-style** | Verbose explanation output style |
| **learning-output-style** | Combined learning + explanatory output |

Official skills repo: `github.com/anthropics/skills/` — includes `frontend-design`, `web-artifacts-builder`, `mcp-builder`, `webapp-testing` (Playwright), `algorithmic-art`, `canvas-design`, `skill-creator`, `docx`/`pdf`/`pptx`/`xlsx`.

## UI/UX & Design Skills (priority for product builders)

| Repo | Stars | What it does |
|------|-------|-------------|
| **MariusYvard/NullToHero** | ★59 | **Best all-in-one.** 4 skills (design, SEO, inspect, audit), 59 commands, 95 ref docs, 14 parallel sub-agents. Full web team in Claude: build/amplify/polish/simplify/animate/layout/adapt/mobile/delight/launch. Scores sites 0-100. WCAG-checked design system generator. |
| **oldbrush/skill-top-design-systems** | ★25 | Top 20 design systems reference (Material, Polaris, Ant, Fluent 2, Primer, Spectrum, Carbon, Chakra, Radix, Mantine, MUI). 60+ component patterns. Planning decision framework. |
| **ajantoniou/fable-design-system** | ★5 | Free design taste injection. Warm paper backgrounds, real type pairings, fluid clamp() spacing, pill CTAs, soft shadows, motion with restraint. Self-critiques contrast ratios. Works with Claude, Cursor, Codex. |
| **pato-gonzalez/design-system-stack** | ★4 | 4-skill bundle: extract tokens from live sites, design-system-patterns (Style Dictionary, theming), 185-indexed design system catalog, animated-landing Awwwards pipeline. |
| **voidmatcha/ui-clone-skills** | ★5 | Reverse-engineer live URLs into React+Tailwind. Downloads real CSS, getComputedStyle, extracts GSAP/Framer params. AE/SSIM visual verification. Near-zero vision tokens. |
| **Bbasche/design-review** | ★2 | UI review like a design director. Screenshots 3 viewports, extracts design system from code, 50+ taste rules, severity-ranked report with file:line references. Figma comparison mode. |
| **qubernetic/wireframe-agent-skill** | ★1 | B&W wireframe mockups in React+Tailwind. Grayscale, dashed borders, monospace, X-pattern placeholders. 11 reusable components. |
| **a1e99/a1ex-Claude-code-ui-ux-ai-skills** | ★1 | 12 professional UI/UX skills: audit builder, mobile app design, webapp review, design system builder, component specs, landing page review, dashboard review, accessibility, UX writing, handoff, CRO. |
| **deandreperry/ai-code-skills-lab** | ★1 | 50 production skills across 6 categories: Frontend (9), Accessibility (7), Design Systems (10), Testing (7), Docs (7), UX (10). WCAG audit, Figma-to-code, Playwright tests, empty state review. |
| **angelapaia/frontend-design-engineer-skill** | ★4 | Art Director + Sr Frontend Engineer in a skill. 8 curated visual directions (Editorial Serif, Swiss Minimal, Luxury Dark, Neo-Brutalist, etc.), 60+ components from shadcn/MagicUI/ReactBits/21st.dev/Aceternity, GSAP animations, WCAG AA. |
| **akashsahu0612/website-redesign-skill** | ★3 | 8-phase redesign workflow: discovery → design system → component sourcing (21st.dev MCP) → section build → Framer Motion → UX polish → assets → review. |
| **msdakot/ai-foundary** | ★5 | Open registry of production-ready skills, agents, plugins, and contexts. Includes devops-agent (15 sub-agents: brainstorm→spec→architect→dev→review→deploy) and ai-data-agents (13 sub-agents: research→data→model→deploy). |
| **nextlevelbuilder/ui-ux-pro-max-skill** | ★100K | **The most-starred UI/UX skill on GitHub.** 67 UI styles (Minimalism, Glassmorphism, Neumorphism, Brutalism, Bento Grid, Cyberpunk, AI-Native, Soft UI, Liquid Glass, Aurora, Neo-Brutalism, Y2K, etc.), 161 industry-matched color palettes, 57 font pairings, 99 UX guidelines, 161 industry-specific reasoning rules, 25 chart types, 22 tech stack targets (React, Next.js, Vue, Svelte, SwiftUI, Flutter, shadcn/ui, Angular, Laravel, Three.js, JavaFX, WPF, etc.). v2.0 Design System Generator analyzes project requirements and outputs complete token sets + anti-patterns to avoid + pre-delivery checklists. |

## Component & UI Library Skills

Skills that make Claude use existing component libraries, registries, and design systems instead of writing UI from scratch.

| Repo | Stars | What it does |
|------|-------|-------------|
| **bitjaru/styleseed** | ★635 | **Design engine for AI coding — teaches judgment, not just data.** 74 visual rules, 48 components, 7 brand skins (Toss, Raycast, Arc, etc.). Named motion system (Snap, Flow, Bounce, Glide). Scored Quality Gate reviews + fixes UI to ≥80/100 before you see it. Fights the generic AI look: default indigo, icon-chip cliché, rainbow lists, template layouts. Anti-drift STYLESEED.md lock persists across sessions. Ships CLAUDE.md + AGENTS.md + .cursorrules. Install: `npx skills add bitjaru/styleseed` or paste the LLMs.txt URL into any agent. |
| **masonjames/Shadcnblocks-Skill** | ★18 | Gives Claude knowledge of **1,338 shadcn/ui blocks** (hero, pricing, testimonial, FAQ, navbar, footer, dashboard, charts, data tables) + **1,189 components** across 60+ groups. Claude selects the right block for any frontend task automatically. |
| **trin-zenityx/21st-dev-builder-v2** | ★1 | 8-phase workflow for building with **1,400+ shadcn/ui components** from 21st.dev marketplace. Live component discovery (browses current catalog, never relies on memory), installs via npx shadcn add, applies 8 post-install compatibility fixes. |
| **cruzedevelopment/use-ui-libraries** | ★2 | Decision flow skill: checks project's existing library first → component registries (MagicUI, Aceternity, Origin UI, 21st.dev, Cult UI, Kokonut) → AI-specific (AI SDK Elements, CopilotKit) → enterprise design systems (Fluent, Carbon, Polaris, Primer, Lightning, Geist) → only then builds custom. |
| **rushikeshsakharleofficial/frontend-components-skill** | — | Classifies page type and domain, matches to 21st.dev categories, blocks paid/pro components, ranks free candidates with 9-factor weighted formula (requirement fit 30% + category match 20% + free tier confidence 15% + ...). Returns top 3-5, installs best one. |
| **Gmandonut/claude-shadcn-skill** | — | Dedicated shadcn/ui component knowledge skill for Claude Code. |
| **objetiva-comercios/shadcn-tabler** | — | Transforms all shadcn/ui components to match Tabler UI aesthetic — 3-layer CSS variable system, 46 transformed components. |

### Component registries (for reference)

The registries these skills tap into:

| Registry | URL | Focus | Install command |
|----------|-----|-------|-----------------|
| **shadcn/ui** | ui.shadcn.com | Base component library (default for new projects) | `npx shadcn@latest add <component>` |
| **21st.dev** | 21st.dev | Largest shadcn/ui marketplace — 1400+ community components | `npx @21st-dev/registry add` or MCP |
| **ShadcnBlocks** | shadcnblocks.com | 1338 blocks + 1189 components — paid API key required | `npx shadcn add @shadcnblocks/<block-id>` |
| **Magic UI** | magicui.design | Animated components, landing page sections | `npx shadcn add https://magicui.design/r/<component>` |
| **Aceternity UI** | ui.aceternity.com | Beautiful animations and effects | Copy-paste from docs |
| **Origin UI** | originui.com | Polished copy-paste components | `npx shadcn add https://originui.com/r/<component>` |
| **Cult UI** | cultui.com | Community-driven registry | `npx shadcn add https://cult-ui.com/r/<component>` |
| **Kokonut UI** | kokonut.dev | Animated, accessible components | Copy-paste from docs |
| **AI SDK Elements** | elements.ai-sdk.dev | Chat, code, voice, workflow on shadcn/ui | `npx shadcn add https://elements.ai-sdk.dev/r/<component>` |
| **CopilotKit** | copilotkit.ai | Framework for AI copilots in apps | `npm install @copilotkit/react-core` |

## Product-Building & Shipping Frameworks

| Repo | Stars | What it does |
|------|-------|-------------|
| **multica-ai/andrej-karpathy-skills** | ★186K | Karpathy's 4 principles: Think Before Coding, Simplicity First, Surgical Changes, Goal-Driven Execution. Single CLAUDE.md. Free quality improvement on every session. |
| **hesreallyhim/awesome-claude-code** | ★47K | Biggest curated list of skills, hooks, agents, plugins for Claude Code |
| **travisvn/awesome-claude-skills** | ★13K | Curated Claude skills — official + community |
| **obra/superpowers** | ★20K | 20+ battle-tested skills. TDD (red-green-refactor), brainstorm, write-plan, execute-plan, subagent dispatch, code review loops, git worktrees. Hooks for session-start + verification. |
| **garrytan/gstack** | (YC CEO) | **Virtual engineering team by YC's CEO.** 25+ slash commands: office-hours, plan-ceo-review, plan-eng-review, plan-design-review, review, ship, land-and-deploy, canary, qa, design-review, cso (security), autoplan, retro, investigate, freeze/guard/unfreeze, benchmark, browse, connect-chrome. 55 SKILL.md files. Works on Claude Code, Codex, Cursor, OpenCode, Factory, Slate. Auto-updates via team mode. |
| **stefan-stepzero/shipkit** | ★1 | 39 skills + 8 agent personas. Full product lifecycle: Why → Discovery → Spec → Roadmap → Plan → Ship → Review → QA → Deploy. Includes ux-audit, qa-visual (Playwright), codebase-audit (dead code, orphans), scale-ready audit, prompt-audit, preflight. |
| **TheDecipherist/claude-code-mastery** | ★537 | Complete guide + starter kit. 16 slash commands, deterministic hooks, 3-layer security, MongoDB wrapper, CLAUDE.md template. |
| **coleam00/helpline** | ★100 | CLAUDE.md hierarchy demo (hooks → skills → LSP → MCP → plugin architecture) |
| **ZhongliangGuo/oop-architect** | ★95 | Live Mermaid UML diagrams in CLAUDE.md that auto-update as you code |

### Comprehensive Frameworks (all-in-one)

| Repo | Stars | What it includes |
|------|-------|-----------------|
| **affaan-m/everything-claude-code** | ★17K | 28 agents, 59 commands, 116 skills, 26 hooks, 27 hook scripts, language rules for 13 languages, autonomous loop management |
| **CloudAI-X/claude-workflow-v2** | ★1.3K | Universal workflow plugin — agents + skills + hooks + commands in one package |
| **jeremylongshore/claude-code-plugins-plus-skills** | ★1.6K | 340 plugins + 1,367 agent skills with CCPI package manager, interactive tutorials |
| **diet103/claude-code-infrastructure-showcase** | ★9.3K | Full Claude Code infrastructure showcase with skill auto-activation, hooks, agents |
| **ChrisWiles/claude-code-showcase** | ★5.5K | Project config combining hooks, skills, agents, commands, and GitHub Actions |
| **claude-forge (sangrokjung)** | ★593 | oh-my-zsh-inspired plugin framework: 11 AI agents, 36 commands, 15 skills, 6-layer security hooks |

## Awesome Lists (gateways to more)

| Repo | Stars | Description |
|------|-------|-------------|
| **hesreallyhim/awesome-claude-code** | ★47K | Skills, hooks, agents, plugins, orchestrators |
| **travisvn/awesome-claude-skills** | ★13K | Claude skills — official + community |
| **Prat011/awesome-llm-skills** | ★1.3K | Universal LLM skills (Claude, Codex, Gemini, Qwen) |
| **ithiria894/awesome-claude-code-workflows** | ★106 | Workflow recipes combining hooks+MCP+skills+agents |
| **kodustech/awesome-agent-skills** | ★85 | Agent skills for Claude Code, Codex, Cursor |

## Installation Quick Reference

### Methods ranked by convenience

| Method | Command | Scope |
|--------|---------|-------|
| **Plugin marketplace** | `/plugin marketplace add <author>/<repo>` then `/plugin install <name>` | Global (auto-updates) |
| **skills.sh CLI** | `npx skills add <author>/<repo>@<skill-name> [--global] [--yes]` | Global or project |
| **Clone to skills dir** | `git clone <url> ~/.claude/skills/<name>/` | Global (Claude Code) |
| **Single SKILL.md** | `curl -o .claude/skills/<name>/SKILL.md <raw-url>` | Per project |
| **Manual copy** | `mkdir -p ~/.claude/skills/<name> && cp SKILL.md ~/.claude/skills/<name>/` | Global |
| **Symlink** | `ln -sf ~/.agents/skills/<name> ~/.claude/skills/<name>` | Global (shared repo) |

### Per-agent locations

| Agent | Skills directory |
|-------|-----------------|
| **Claude Code** | `~/.claude/skills/<name>/SKILL.md` (global), `.claude/skills/<name>/SKILL.md` (project) |
| **Codex CLI** | `~/.codex/skills/<name>/SKILL.md` |
| **Cursor** | `.cursor/rules/<name>.mdc` (project) or `~/.cursor/rules/` (global) |
| **Gemini / Antigravity** | `~/.gemini/config/plugins/<name>/skills/<name>/SKILL.md` |
| **OpenCode** | `~/.config/opencode/skills/<name>/` |
| **Windsurf** | `~/.windsurf/skills/` |

### Reload after install

```
/reload-skills     # Claude Code
```

Or start a new Claude Code session.
