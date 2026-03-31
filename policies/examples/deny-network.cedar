// Deny all network access: blocks fetch requests and git network operations.
// Useful for air-gapped environments or strict offline-only workflows.

@id("deny-network-fetch")
@name("Deny network fetch")
@description("Blocks outbound HTTP/network requests")
forbid(
    principal,
    action == Action::"network:fetch",
    resource
);

@id("deny-git-network")
@name("Deny git network ops")
@description("Blocks git fetch, pull, and similar network operations")
forbid(
    principal,
    action == Action::"git::network",
    resource
);

@id("deny-git-push")
@name("Deny git push")
@description("Blocks pushing commits to remote repositories")
forbid(
    principal,
    action == Action::"git:push",
    resource
);
