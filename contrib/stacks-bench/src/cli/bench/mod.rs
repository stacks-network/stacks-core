// Copyright (C) 2025-2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use crate::cli::common::{BoxedOutput, CliContext, ExecCommand, boxed};

pub mod bench_ui;
pub mod list;
pub mod remove;
pub mod rerun;
pub mod run;
pub mod show;

#[derive(clap::Subcommand, Debug)]
pub enum BenchCommand {
    Run(Box<run::RunArgs>),
    /// Re-run an existing benchmark using its original parameters.
    Rerun(rerun::RerunArgs),
    #[command(alias = "rm")]
    Remove(remove::RemoveArgs),
    #[command(alias = "ls")]
    List(list::ListArgs),
    /// Show details and profiler data for a benchmark run.
    Show(show::ShowArgs),
}

#[derive(clap::Args, Debug)]
pub struct BenchArgs {
    #[command(subcommand)]
    pub command: BenchCommand,
}

impl ExecCommand for BenchArgs {
    type Output = BoxedOutput;

    async fn exec(&self, ctx: &CliContext) -> anyhow::Result<BoxedOutput> {
        match &self.command {
            BenchCommand::Run(args) => Ok(boxed(args.exec(ctx).await?)),
            BenchCommand::Rerun(args) => Ok(boxed(args.exec(ctx).await?)),
            BenchCommand::Remove(args) => Ok(boxed(args.exec(ctx).await?)),
            BenchCommand::List(args) => Ok(boxed(args.exec(ctx).await?)),
            BenchCommand::Show(args) => Ok(boxed(args.exec(ctx).await?)),
        }
    }
}
