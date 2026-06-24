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

use anyhow::{Result, bail};
use console::style;

use crate::cli::common::{CliContext, ExecCommand, run_db_cleanup};
use crate::commands::chainstate::remove::{self, RemoveResult};

#[derive(clap::Args, Debug)]
pub struct RemoveArgs {
    /// The ID of the chainstate(s) to delete. If omitted, an interactive
    /// selector is shown with all available chainstates.
    #[arg(long, alias = "id")]
    pub chainstate_id: Option<Vec<u32>>,

    /// Skip the confirmation prompt.
    #[arg(long, short = 'y', default_value_t = false)]
    pub yes: bool,
}

impl ExecCommand for RemoveArgs {
    type Output = RemoveResult;

    async fn exec(&self, ctx: &CliContext) -> Result<Self::Output> {
        let interactive = ctx.interactive();
        let mut app_db = ctx.app_db();

        let chainstate_ids: Vec<i32> = if let Some(ids) = &self.chainstate_id {
            let mut converted: Vec<i32> = ids
                .iter()
                .map(|&id| {
                    i32::try_from(id).map_err(|_| {
                        anyhow::anyhow!("chainstate ID {id} exceeds maximum ({})", i32::MAX)
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            converted.sort_unstable();
            converted.dedup();
            converted
        } else if !interactive {
            bail!("--chainstate-id is required in non-interactive mode");
        } else {
            let chainstates = app_db.list_chainstates().await?;
            if chainstates.is_empty() {
                cliclack::log::info("No chainstates found.")?;
                return Ok(RemoveResult {
                    deleted_chainstate_ids: vec![],
                    message: "No chainstates found.".into(),
                });
            }

            // Collect labels before creating the multiselect (MultiSelect is !Send)
            let mut items = Vec::with_capacity(chainstates.len());
            for cs in &chainstates {
                let network_name = app_db.get_network_name(cs.network_id).await?;
                let run_count = app_db.count_benchmark_runs_for_chainstate(cs.id).await?;
                items.push((
                    cs.id,
                    format!("Chainstate {}", cs.id),
                    format!(
                        "{network_name} | chain_id={} | tip_height={} | {run_count} run{}",
                        cs.chain_id,
                        cs.tip_height,
                        if run_count == 1 { "" } else { "s" }
                    ),
                ));
            }

            let mut select = cliclack::multiselect(format!(
                "Select chainstates to delete ({} available)",
                chainstates.len()
            ));
            for (id, label, hint) in items {
                select = select.item(id, label, hint);
            }
            let chosen: Vec<i32> = select.filter_mode().interact()?;
            if chosen.is_empty() {
                cliclack::log::info("No chainstates selected.")?;
                return Ok(RemoveResult {
                    deleted_chainstate_ids: vec![],
                    message: "No chainstates selected.".into(),
                });
            }
            chosen
        };

        // Validate chainstates exist
        let mut chainstates = Vec::with_capacity(chainstate_ids.len());
        for &id in &chainstate_ids {
            match app_db.get_chainstate(id).await? {
                Some(cs) => chainstates.push(cs),
                None => bail!("Chainstate {} not found", id),
            }
        }

        // Interactive confirmation
        if interactive {
            for cs in &chainstates {
                let network_name = app_db.get_network_name(cs.network_id).await?;
                let run_count = app_db.count_benchmark_runs_for_chainstate(cs.id).await?;
                cliclack::log::step(format!(
                    "Chainstate {} — {} | tip_height={} | {run_count} associated run{}",
                    style(cs.id).bold(),
                    network_name,
                    cs.tip_height,
                    if run_count == 1 { "" } else { "s" },
                ))?;
            }

            if !self.yes {
                let label = if chainstates.len() == 1 {
                    format!(
                        "Delete chainstate {} and all associated data (including benchmark runs)?",
                        chainstates[0].id
                    )
                } else {
                    format!(
                        "Delete {} chainstates and all associated data (including benchmark runs)?",
                        chainstates.len()
                    )
                };
                if !cliclack::confirm(label).interact()? {
                    cliclack::log::info("Aborted.")?;
                    return Ok(RemoveResult {
                        deleted_chainstate_ids: vec![],
                        message: "Aborted.".into(),
                    });
                }
            }
        }

        // Delete — non-interactive delegates entirely; interactive shows spinners
        if !interactive {
            return remove::delete_chainstates(&mut app_db, &chainstate_ids, true).await;
        }

        let multi = cliclack::multi_progress(format!(
            "Deleting {} chainstate{}",
            chainstates.len(),
            if chainstates.len() == 1 { "" } else { "s" }
        ));

        for cs in &chainstates {
            let spinner = multi.add(cliclack::spinner());
            spinner.start(format!("Deleting chainstate {}…", cs.id));
            app_db.delete_chainstate(cs.id).await?;
            spinner.stop(fmt_success!("Chainstate {} deleted", cs.id));
        }

        multi.stop();

        run_db_cleanup(app_db, false).await?;

        Ok(RemoveResult {
            message: format!("{} chainstate(s) deleted", chainstate_ids.len()),
            deleted_chainstate_ids: chainstate_ids,
        })
    }
}
