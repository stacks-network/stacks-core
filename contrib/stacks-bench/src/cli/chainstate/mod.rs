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

pub mod index;
pub mod list;
pub mod remove;

use clap::Subcommand;

use crate::cli::common::{BoxedOutput, CliContext, ExecCommand, boxed};

#[derive(Subcommand, Debug)]
pub enum ChainstateCommand {
    /// Index a range of blocks from the node database
    Index(index::IndexArgs),
    /// List indexed chainstates
    #[command(alias = "ls")]
    List(list::ListArgs),
    /// Delete one or more chainstates and all associated data
    #[command(alias = "rm")]
    Remove(remove::RemoveArgs),
}

#[derive(clap::Args, Debug)]
pub struct ChainstateArgs {
    #[command(subcommand)]
    pub command: ChainstateCommand,
}

impl ExecCommand for ChainstateArgs {
    type Output = BoxedOutput;

    async fn exec(&self, ctx: &CliContext) -> anyhow::Result<BoxedOutput> {
        match &self.command {
            ChainstateCommand::Index(args) => Ok(boxed(args.exec(ctx).await?)),
            ChainstateCommand::List(args) => Ok(boxed(args.exec(ctx).await?)),
            ChainstateCommand::Remove(args) => Ok(boxed(args.exec(ctx).await?)),
        }
    }
}
