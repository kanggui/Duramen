# Adding Command Handlers

When an agent sends a shell command (via `powershell` or `bash` tools), Duramen's request adaptor parses the command string to determine the Cedar action and resource. Command handlers provide **per-binary parsing logic** so that specific tools (like `git`) produce precise, policy-friendly authorization requests instead of generic `shell:<binary>` actions.

## How It Works

```
"git push --force origin main"
    │
    ▼
┌─────────────────────────┐
│  parse_shell_command()  │  strips sudo/env/nohup/nice/time prefixes
│  (copilot_cli.rs)       │  extracts binary name: "git"
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  get_command_handler()  │  looks up "git" → GitCommandHandler
│  (commands/mod.rs)      │  not found? → DefaultCommandHandler
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  GitCommandHandler      │  parses subcommand + flags
│  (commands/git.rs)      │  returns action: "git::destructive"
│                         │  returns resource: GitRef::"main"
└─────────────────────────┘
```

## The `CommandHandler` Trait

```rust
// crates/request-adaptor/src/commands/mod.rs

pub struct CommandParseResult {
    pub action: String,
    pub resource: AuthzResource,
}

pub trait CommandHandler {
    /// The binary name this handler matches (e.g., "git", "docker").
    fn binary_name(&self) -> &str;

    /// Parse the command arguments into a Cedar action and resource.
    /// `args` is everything after the binary name (prefix-stripped).
    /// `cwd` is the working directory if available.
    fn parse(&self, args: &[&str], cwd: Option<&str>) -> CommandParseResult;
}
```

The handler returns a `CommandParseResult` with:
- **`action`** — the Cedar action name (e.g., `git::read`, `docker:build`)
- **`resource`** — the Cedar resource entity with type, ID, and attributes

## Built-in Handlers

### `GitCommandHandler` (`commands/git.rs`)

Classifies git subcommands into four tiers:

| Git action | Cedar action | Trigger |
|---|---|---|
| `status`, `log`, `diff`, `show`, `branch` | `git::read` | Read-only operations |
| `add`, `commit`, `checkout`, `switch`, `stash`, `merge`, `rebase` | `git::write` | Local mutations |
| `push`, `fetch`, `pull`, `clone` | `git::network` | Remote operations |
| `push --force`, `reset --hard`, `branch -d/-D`, `clean -f/-fd` | `git::destructive` | Irreversible operations |

Resources are `GitRef` with attributes: `is_destructive`, `remote`.

### `DefaultCommandHandler` (`commands/default.rs`)

Fallback for unregistered binaries. Detects:
- URL arguments → `Url` resource
- File path arguments → `File` resource (resolved relative to `cwd`)
- No arguments → `File` resource using `cwd`

The action is overridden by the caller to `shell:<binary>` (e.g., `shell:cargo`, `shell:npm`).

## Adding a New Handler

### Example: Docker handler

**1. Create the handler file**

```rust
// crates/request-adaptor/src/commands/docker.rs

use super::{CommandHandler, CommandParseResult};
use duramen_engine::entities::AuthzResource;

pub struct DockerCommandHandler;

impl CommandHandler for DockerCommandHandler {
    fn binary_name(&self) -> &str {
        "docker"
    }

    fn parse(&self, args: &[&str], _cwd: Option<&str>) -> CommandParseResult {
        let subcommand = args.first().copied().unwrap_or("info");

        let (action, resource) = match subcommand {
            "build" => {
                let context = args.last().copied().unwrap_or(".");
                ("docker:build", AuthzResource::file(context))
            }
            "push" => {
                let image = args.last().copied().unwrap_or("unknown");
                ("docker:push", AuthzResource::url(image))
            }
            "run" | "exec" => {
                let image = args.iter()
                    .filter(|a| !a.starts_with('-'))
                    .nth(1)
                    .copied()
                    .unwrap_or("unknown");
                ("docker:run", AuthzResource::command(image))
            }
            _ => ("docker:other", AuthzResource::command(subcommand)),
        };

        CommandParseResult {
            action: action.to_string(),
            resource,
        }
    }
}
```

**2. Register the handler**

```rust
// crates/request-adaptor/src/commands/mod.rs

pub mod default;
pub mod docker;  // ← add
pub mod git;

pub fn get_command_handler(binary: &str) -> Option<Box<dyn CommandHandler>> {
    match binary {
        "git" => Some(Box::new(git::GitCommandHandler)),
        "docker" => Some(Box::new(docker::DockerCommandHandler)),  // ← add
        _ => None,
    }
}
```

**3. Add Cedar actions to the schema** (if using new action names)

```cedar
// policies/default/schema.cedarschema

action "docker:build" appliesTo {
    principal: [Agent],
    resource: [File],
};

action "docker:push" appliesTo {
    principal: [Agent],
    resource: [Url],
};

action "docker:run" appliesTo {
    principal: [Agent],
    resource: [Command],
};
```

**4. Write policies for the new actions**

```cedar
// .authz/docker-policy.cedar

@id("deny-docker-push")
@name("Deny Docker push")
@description("Blocks pushing Docker images to registries")
forbid(
    principal,
    action == Action::"docker:push",
    resource
);
```

**5. Add tests**

```rust
// crates/request-adaptor/src/commands/docker.rs

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_build_maps_to_file() {
        let result = DockerCommandHandler.parse(&["build", "."], Some("/project"));
        assert_eq!(result.action, "docker:build");
    }

    #[test]
    fn docker_push_maps_to_url() {
        let result = DockerCommandHandler.parse(&["push", "myapp:latest"], None);
        assert_eq!(result.action, "docker:push");
    }
}
```

## Key Design Notes

- **Handlers only parse** — they don't evaluate policies or make authorization decisions
- **The `action` string must match a Cedar action** in the schema for schema-validated policies to work. For unvalidated policies, any action string works.
- **Resource attributes** flow through to Cedar entity attributes — set `is_destructive`, `is_protected`, etc. on `resource.attributes` to enable attribute-based policies
- **Unregistered binaries** fall through to `DefaultCommandHandler`, which produces `shell:<binary>` actions — no handler needed for basic coverage
- **Prefix stripping** happens before the handler is called — `sudo docker push` arrives as `binary="docker"`, `args=["push", ...]` with `is_elevated=true`

## Enrichment Pipeline

After command handlers parse the binary and args into an action and resource, the **enrichment pipeline** runs two additional stages to add attributes and potentially reclassify the action.

### Stage 2: Resource Enrichers

Enrichers add attributes to the resource without changing the action. They run in registration order.

| Enricher | What it does |
|----------|-------------|
| `PathSensitivityEnricher` | Sets `is_protected=true` for `.env`, `*.pem`, `.ssh/`, CI configs, lock files |
| `FileMetadataEnricher` | Extracts `extension` and `directory` from file paths |
| `NetworkDomainEnricher` | Extracts `domain` from URL resources |
| `ElevationEnricher` | Sets `is_elevated` based on sudo detection |

### Stage 3: Action Classifiers

Classifiers can reclassify the action based on the enriched resource and command context.

| Classifier | What it does |
|-----------|-------------|
| `DestructiveClassifier` | Pattern-based destructive command detection |
| `PackageInstallClassifier` | Detects `apt/pip/npm/cargo install` → reclassifies to `package:install` |

### Adding a new enricher

```rust
// crates/request-adaptor/src/enrichers/my_enricher.rs
use crate::pipeline::{PipelineContext, ResourceEnricher};
use duramen_engine::entities::AuthzResource;

pub struct MyEnricher;

impl ResourceEnricher for MyEnricher {
    fn name(&self) -> &str { "my-enricher" }
    fn enrich(&self, resource: &mut AuthzResource, ctx: &PipelineContext) {
        // Add attributes based on resource/context inspection
    }
}
```

Register in `copilot_cli.rs::default_pipeline()`:
```rust
p.add_enricher(Box::new(my_enricher::MyEnricher::new()));
```
