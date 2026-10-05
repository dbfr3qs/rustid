//! Queries over admin entities (the query and
//! `QueryResult`): sort direction, the page, offset or continuation-token
//! range, and the paged result.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::AdminError;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Direction {
    #[default]
    Ascending,
    Descending,
}

/// The page size when a query names none.
pub const DEFAULT_PAGE_SIZE: u32 = 25;
/// The largest page size a query can ask for.
pub const MAX_PAGE_SIZE: u32 = 1000;

/// A 1-based page, an offset, or a continuation token (none
/// for the beginning).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Range {
    Page { page: u32, size: u32 },
    Offset { skip: u64, take: u32 },
    Token { token: Option<String>, size: u32 },
}

impl Default for Range {
    fn default() -> Self {
        Range::Page {
            page: 1,
            size: DEFAULT_PAGE_SIZE,
        }
    }
}

/// `QueryResult`: a page of items and where it sits.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryResult<T> {
    pub items: Vec<T>,
    pub total_count: u64,
    pub total_pages: u64,
    pub has_more_data: bool,
    pub next_token: Option<String>,
    pub previous_token: Option<String>,
}

fn check_size(size: u32, property: &str) -> Result<u64, AdminError> {
    if size == 0 || size > MAX_PAGE_SIZE {
        return Err(AdminError::invalid_value(
            property,
            format!("Must be between 1 and {MAX_PAGE_SIZE}."),
        ));
    }
    Ok(u64::from(size))
}

fn encode(offset: u64) -> String {
    URL_SAFE_NO_PAD.encode(offset.to_string())
}

fn decode(token: &str) -> Option<u64> {
    let bytes = URL_SAFE_NO_PAD.decode(token).ok()?;
    std::str::from_utf8(&bytes).ok()?.parse().ok()
}

/// The page `range` names of already filtered and sorted `items`.
pub fn paginate<T>(items: Vec<T>, range: &Range) -> Result<QueryResult<T>, AdminError> {
    let (skip, take) = match range {
        Range::Page { page, size } => {
            let size = check_size(*size, "PageSize")?;
            if *page == 0 {
                return Err(AdminError::invalid_value("Page", "Must be at least 1."));
            }
            ((u64::from(*page) - 1) * size, size)
        }
        Range::Offset { skip, take } => (*skip, check_size(*take, "Take")?),
        Range::Token { token, size } => {
            let size = check_size(*size, "PageSize")?;
            let skip = match token {
                None => 0,
                Some(token) => decode(token).ok_or_else(|| {
                    AdminError::invalid_value("ContinuationToken", "Invalid continuation token.")
                })?,
            };
            (skip, size)
        }
    };
    let total = items.len() as u64;
    let end = skip.saturating_add(take).min(total);
    let page: Vec<T> = items
        .into_iter()
        .skip(usize::try_from(skip).unwrap_or(usize::MAX))
        .take(usize::try_from(take).unwrap_or(usize::MAX))
        .collect();
    let has_more_data = end < total;
    Ok(QueryResult {
        items: page,
        total_count: total,
        total_pages: total.div_ceil(take),
        has_more_data,
        next_token: has_more_data.then(|| encode(end)),
        previous_token: (skip > 0).then(|| encode(skip.saturating_sub(take))),
    })
}
