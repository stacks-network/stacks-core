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

//! MCP resource handlers — schema discovery.
//!
//! Exposes the live database DDL (from `sqlite_master`) as MCP resources so
//! agents can introspect the schema without running ad-hoc SQL.

use anyhow::{Error, Result};
use rmcp::model::*;
use stacks_bench::db::app::AppDb;

// ---------------------------------------------------------------------------
// Resource list & templates (static — these don't need a DB connection)
// ---------------------------------------------------------------------------

/// Static resource: the full schema.
pub fn list_resources() -> ListResourcesResult {
    ListResourcesResult {
        resources: vec![RawResource::new("stacks-bench://schema", "Database Schema")
            .with_description(
                "Full SQL DDL for the stacks-bench database (excluding internal/staging tables)",
            )
            .with_mime_type("text/plain")
            .no_annotation()],
        ..Default::default()
    }
}

/// Template for per-table lookup.
pub fn list_resource_templates() -> ListResourceTemplatesResult {
    ListResourceTemplatesResult {
        resource_templates: vec![
            RawResourceTemplate::new("stacks-bench://schema/{table}", "Table Schema")
                .with_description("DDL for a single table and its indexes")
                .with_mime_type("text/plain")
                .no_annotation(),
        ],
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Resource read (requires a live DB connection)
// ---------------------------------------------------------------------------

/// Read a resource by URI, querying `sqlite_master` for DDL.
pub async fn read_resource(uri: &str, db: &AppDb) -> Result<ReadResourceResult, ErrorData> {
    if uri == "stacks-bench://schema" {
        let ddl = full_schema(db).await.map_err(internal)?;
        return Ok(ReadResourceResult::new(vec![
            ResourceContents::text(ddl, uri).with_mime_type("text/plain"),
        ]));
    }

    if let Some(table) = uri.strip_prefix("stacks-bench://schema/") {
        let ddl = table_schema(db, table).await.map_err(internal)?;
        let ddl = ddl.ok_or_else(|| {
            ErrorData::resource_not_found(format!("No table '{table}' in schema"), None)
        })?;
        return Ok(ReadResourceResult::new(vec![
            ResourceContents::text(ddl, uri).with_mime_type("text/plain"),
        ]));
    }

    Err(ErrorData::resource_not_found(
        format!("Unknown resource URI: {uri}"),
        None,
    ))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Full DDL for all non-internal tables and their indexes.
async fn full_schema(db: &AppDb) -> Result<String> {
    let rows = db.get_schema_ddl().await?;
    let stmts: Vec<String> = rows
        .into_iter()
        .filter_map(|r| r.sql.map(|s| format!("{s};")))
        .collect();
    Ok(stmts.join("\n\n"))
}

/// DDL for a single table + its indexes. Returns `None` if no matching table.
async fn table_schema(db: &AppDb, name: &str) -> Result<Option<String>> {
    let lower = name.to_lowercase();
    let rows = db.get_schema_ddl().await?;
    let stmts: Vec<String> = rows
        .into_iter()
        .filter(|r| {
            let matches_table = r.object_type == "table" && r.name.to_lowercase() == lower;
            let matches_index = r.object_type == "index"
                && r.tbl_name.as_deref().map(|t| t.to_lowercase()) == Some(lower.clone());
            matches_table || matches_index
        })
        .filter_map(|r| r.sql.map(|s| format!("{s};")))
        .collect();
    if stmts.is_empty() {
        Ok(None)
    } else {
        Ok(Some(stmts.join("\n\n")))
    }
}

/// Convert an `anyhow::Error` into an MCP internal error.
fn internal(e: Error) -> ErrorData {
    ErrorData::internal_error(format!("{e:#}"), None)
}
