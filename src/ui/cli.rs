use clap::{Parser, Subcommand};

use crate::ui::runner::AppAction;

#[derive(Parser)]
#[command(name = "dsign")]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Command,
}

#[derive(Subcommand)]
pub enum Command {
    Init { threshold: usize, n: usize },
    Server { index: usize },
    Client { message: String, threshold: usize },
}

impl From<Command> for AppAction {
    fn from(cmd: Command) -> Self {
        match cmd {
            Command::Init { threshold, n } => AppAction::Init { threshold, n },
            Command::Server { index } => AppAction::Server { index },
            Command::Client { message, threshold } => AppAction::Client { message, threshold },
        }
    }
}
