use clap::{Parser, Subcommand};

mod commands;

#[derive(Parser)]
#[command(name = "duramen", version, about = "Fine-grained authorization for AI coding agents")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Evaluate an authorization request
    Check {
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        principal: Option<String>,
        #[arg(long)]
        action: Option<String>,
        #[arg(long)]
        resource: Option<String>,
        #[arg(long, default_value = "file")]
        resource_type: String,
        #[arg(long)]
        context: Option<String>,
        #[arg(long)]
        policy_dir: Option<String>,
        #[arg(long)]
        audit_log: Option<String>,
    },
    /// Validate Cedar policies against the schema
    Validate {
        #[arg(long, default_value = ".authz")]
        policy_dir: String,
    },
    /// Initialize .authz/ directory with default policies
    Init,
    /// Query the audit log
    Audit {
        /// Path to audit log file
        #[arg(long)]
        log_path: Option<String>,
        /// Filter entries from last duration (e.g., "1h", "24h", "7d")
        #[arg(long)]
        since: Option<String>,
        /// Filter by decision tier (allow, deny, audit, require-approval)
        #[arg(long)]
        decision: Option<String>,
        /// Filter by principal (e.g., "CopilotCLI")
        #[arg(long)]
        principal: Option<String>,
        /// Maximum number of entries to display
        #[arg(long, default_value = "50")]
        limit: usize,
    },
}

fn main() {
    let cli = Cli::parse();
    let exit_code = match cli.command {
        Commands::Check {
            agent,
            principal,
            action,
            resource,
            resource_type,
            context,
            policy_dir,
            audit_log,
        } => commands::check::run(
            agent,
            principal,
            action,
            resource,
            resource_type,
            context,
            policy_dir,
            audit_log,
        ),
        Commands::Validate { policy_dir } => commands::validate::run(&policy_dir),
        Commands::Init => commands::init::run(),
        Commands::Audit {
            log_path,
            since,
            decision,
            principal,
            limit,
        } => commands::audit::run(log_path, since, decision, principal, limit),
    };
    std::process::exit(exit_code);
}
