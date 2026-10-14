//
// Copyright (c) 2025-2026 rustmailer.com (https://rustmailer.com)
//
// This file is part of the Bichon Email Archiving Project
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use crate::common::auth::WrappedContext;
use crate::rest::ApiResult;
use crate::rest::api::ApiTags;
use bichon_core::dashboard::DashboardStats;
use bichon_core::error::code::ErrorCode;
use bichon_core::ext::event_bus::{Event, emit};
use bichon_core::message::search::{AttachmentSearchFilter, SortBy};
use bichon_core::raise_error;
use bichon_core::settings::SystemConfigurations;
use bichon_core::settings::cli::SETTINGS;
use bichon_core::settings::proxy::{Proxy, ProxyTestResult};
use bichon_core::store::blob::BLOB_MANAGER;
use bichon_core::store::tantivy::attachment::ATTACHMENT_MANAGER;
use bichon_core::users::permissions::Permission;
use bichon_core::version::{Notifications, fetch_notifications};
use poem_openapi::OpenApi;
use poem_openapi::param::{Path, Query};
use poem_openapi::payload::{Json, PlainText};
use serde::Serialize;
use std::collections::HashMap;

const MAX_PAYLOAD_VERIFY_PAGE_SIZE: u64 = 100;
const MAX_PAYLOAD_VERIFY_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Default, Serialize, poem_openapi::Object)]
pub struct BlobIntegrityPage {
    pub page: u64,
    pub page_size: u64,
    pub total_items: u64,
    pub total_pages: u64,
    pub references_scanned: u64,
    pub distinct_hashes_scanned: u64,
    pub indexed_missing: u64,
    pub missing_message_hashes: u64,
    pub missing_attachment_hashes: u64,
    pub missing_shared_hashes: u64,
    pub missing_message_references: u64,
    pub missing_attachment_references: u64,
    pub segment_missing: u64,
    pub bounds_invalid: u64,
    pub payload_verified: u64,
    pub payload_failed: u64,
    pub payload_verification_requested: bool,
    pub scan_mode: String,
}

pub struct SystemApi;

#[OpenApi(prefix_path = "/api/v1", tag = "ApiTags::System")]
impl SystemApi {
    /// Bounded, read-only blob integrity check for administrators.
    ///
    /// The default mode checks only the attachment index and segment bounds;
    /// it never contacts IMAP and never returns blob data. `verify_payload`
    /// optionally validates the selected page's compressed payloads, bounded
    /// by the page-size limit.
    #[oai(
        method = "get",
        path = "/blob-integrity",
        operation_id = "get_blob_integrity"
    )]
    async fn get_blob_integrity(
        &self,
        page: Query<Option<u64>>,
        page_size: Query<Option<u64>>,
        verify_payload: Query<Option<bool>>,
        context: WrappedContext,
    ) -> ApiResult<Json<BlobIntegrityPage>> {
        context.require_permission(None, Permission::USER_MANAGE)?;
        let page = page.0.unwrap_or(1);
        let page_size = page_size.0.unwrap_or(100);
        if page == 0 || page_size == 0 || page_size > 1000 {
            return Err(raise_error!(
                "page must be >= 1 and page_size must be between 1 and 1000".into(),
                ErrorCode::InvalidParameter
            )
            .into());
        }
        let verify_payload = verify_payload.0.unwrap_or(false);
        if verify_payload && page_size > MAX_PAYLOAD_VERIFY_PAGE_SIZE {
            return Err(raise_error!(
                format!(
                    "payload verification page_size must be at most {MAX_PAYLOAD_VERIFY_PAGE_SIZE}"
                ),
                ErrorCode::InvalidParameter
            )
            .into());
        }
        let data = ATTACHMENT_MANAGER.search(
            None,
            AttachmentSearchFilter::default(),
            page,
            page_size,
            true,
            SortBy::DATE,
        )?;
        let mut probe_inputs: HashMap<String, (u64, u64, u64)> = HashMap::new();
        let mut out = BlobIntegrityPage {
            page,
            page_size,
            total_items: data.total_items,
            total_pages: data.total_pages.unwrap_or(0),
            payload_verification_requested: verify_payload,
            scan_mode: if verify_payload {
                "index_segment_bounds_payload".into()
            } else {
                "index_segment_bounds".into()
            },
            ..Default::default()
        };
        for attachment in data.items {
            out.references_scanned += 1;
            let entry = probe_inputs
                .entry(attachment.content_hash)
                .or_insert((attachment.size, 0, 0));
            if attachment.is_message {
                entry.1 += 1;
            } else {
                entry.2 += 1;
            }
        }
        if verify_payload {
            let total_bytes = probe_inputs
                .values()
                .try_fold(0u64, |total, (size, _, _)| total.checked_add(*size))
                .ok_or_else(|| {
                    raise_error!(
                        "payload verification size exceeds the supported limit".into(),
                        ErrorCode::InvalidParameter
                    )
                })?;
            if total_bytes > MAX_PAYLOAD_VERIFY_BYTES {
                return Err(raise_error!(
                    format!("payload verification is limited to {MAX_PAYLOAD_VERIFY_BYTES} bytes per page"),
                    ErrorCode::InvalidParameter
                ).into());
            }
        }
        let mut probes = HashMap::new();
        for content_hash in probe_inputs.keys() {
            probes.insert(
                content_hash.clone(),
                BLOB_MANAGER.probe_attachment(content_hash, verify_payload)?,
            );
        }
        out.distinct_hashes_scanned = probes.len() as u64;
        for (content_hash, probe) in &probes {
            if !probe.indexed {
                out.indexed_missing += 1;
                let (_, message_refs, attachment_refs) = probe_inputs
                    .get(content_hash)
                    .expect("probe input exists for every probe");
                if *message_refs > 0 {
                    out.missing_message_references += *message_refs;
                }
                if *attachment_refs > 0 {
                    out.missing_attachment_references += *attachment_refs;
                }
                match (*message_refs > 0, *attachment_refs > 0) {
                    (true, true) => out.missing_shared_hashes += 1,
                    (true, false) => out.missing_message_hashes += 1,
                    (false, true) => out.missing_attachment_hashes += 1,
                    (false, false) => unreachable!("probe has no references"),
                }
            } else if !probe.segment_present {
                out.segment_missing += 1;
            } else if !probe.bounds_valid {
                out.bounds_invalid += 1;
            } else if verify_payload {
                if probe.payload_verified {
                    out.payload_verified += 1;
                } else {
                    out.payload_failed += 1;
                }
            }
        }
        Ok(Json(out))
    }

    /// Retrieves important system notifications for the Bichon service.
    ///
    /// This endpoint returns a consolidated view of all critical system notifications including:
    /// - Available version updates
    /// - License expiration warnings
    #[oai(
        method = "get",
        path = "/notifications",
        operation_id = "get_notifications"
    )]
    async fn get_notifications(&self, context: WrappedContext) -> ApiResult<Json<Notifications>> {
        // The default-password reminder is admin-only: revealing to ordinary
        // users that the admin password is still the public default would be
        // a privilege-escalation hint, not a reminder.
        let is_admin = context.has_permission(None, Permission::USER_MANAGE);
        let notification = fetch_notifications(is_admin)
            .await
            .map_err(|e| raise_error!(format!("{:#?}", e), ErrorCode::InternalError))?;
        Ok(Json(notification))
    }

    /// Get overall dashboard statistics.
    ///
    /// Returns various aggregated metrics about the mail system, such as
    /// total email count, total storage size, index usage, top senders,
    /// recent activity histogram, and more.
    #[oai(
        method = "get",
        path = "/dashboard-stats",
        operation_id = "get_dashboard_stats"
    )]
    async fn get_dashboard_stats(
        &self,
        context: WrappedContext,
    ) -> ApiResult<Json<DashboardStats>> {
        let stats = DashboardStats::get(context.0).await?;
        Ok(Json(stats))
    }

    /// Get the full list of proxy configurations.
    #[oai(method = "get", path = "/list-proxy", operation_id = "list_proxy")]
    async fn list_proxy(&self, _context: WrappedContext) -> ApiResult<Json<Vec<Proxy>>> {
        //The proxy list is visible to all users.
        let proxies = Proxy::list_all()
            .map_err(|e| raise_error!(format!("{:#?}", e), ErrorCode::InternalError))?;
        Ok(Json(proxies))
    }

    /// Delete a specific proxy configuration by ID. Requires root permission.
    #[oai(path = "/proxy/:id", method = "delete", operation_id = "remove_proxy")]
    async fn remove_proxy(
        &self,
        /// The ID of the proxy configuration to delete.
        id: Path<u64>,
        context: WrappedContext,
    ) -> ApiResult<()> {
        context.require_permission(None, Permission::ROOT)?;
        let id = id.0;
        let url = Proxy::get(id)
            .ok()
            .map(|p| p.url)
            .unwrap_or_else(|| format!("proxy-{id}"));
        Proxy::delete(id)?;
        emit(Event::ProxyRemoved {
            user: context.user.username.clone(),
            url,
        });
        Ok(())
    }

    /// Retrieve a specific proxy configuration by ID. Requires root permission.
    #[oai(path = "/proxy/:id", method = "get", operation_id = "get_proxy")]
    async fn get_proxy(
        &self,
        /// The ID of the proxy configuration to retrieve.
        id: Path<u64>,
        context: WrappedContext,
    ) -> ApiResult<Json<Proxy>> {
        context.require_permission(None, Permission::ROOT)?;
        Ok(Json(Proxy::get(id.0)?))
    }

    /// Test whether a proxy can reach a geo lookup service. Requires root permission.
    #[oai(path = "/proxy/:id/test", method = "post", operation_id = "test_proxy")]
    async fn test_proxy(
        &self,
        id: Path<u64>,
        context: WrappedContext,
    ) -> ApiResult<Json<ProxyTestResult>> {
        context.require_permission(None, Permission::ROOT)?;
        Ok(Json(Proxy::test(id.0).await?))
    }

    /// Create a new proxy configuration. Requires root permission.
    #[oai(path = "/proxy", method = "post", operation_id = "create_proxy")]
    async fn create_proxy(&self, url: PlainText<String>, context: WrappedContext) -> ApiResult<()> {
        context.require_permission(None, Permission::ROOT)?;
        let url = url.0;
        let entity = Proxy::new(url.clone());
        entity.save()?;
        emit(Event::ProxyCreated {
            user: context.user.username.clone(),
            url,
        });
        Ok(())
    }

    /// Update the URL of a specific proxy by ID. Requires root permission.
    #[oai(path = "/proxy/:id", method = "post", operation_id = "update_proxy")]
    async fn update_proxy(
        &self,
        id: Path<u64>,
        url: PlainText<String>,
        context: WrappedContext,
    ) -> ApiResult<()> {
        context.require_permission(None, Permission::ROOT)?;
        let id = id.0;
        let url = url.0;
        Proxy::update(id, url.clone())?;
        emit(Event::ProxyUpdated {
            user: context.user.username.clone(),
            url,
        });
        Ok(())
    }

    /// Get system configurations.
    ///
    /// Returns a read-only snapshot of the server configuration
    /// resolved at startup. Sensitive values are not exposed.
    #[oai(
        method = "get",
        path = "/system-configurations",
        operation_id = "get_system_configurations"
    )]
    async fn get_system_configurations(
        &self,
        context: WrappedContext,
    ) -> ApiResult<Json<SystemConfigurations>> {
        context.require_permission(None, Permission::ROOT)?;
        let config: SystemConfigurations = SystemConfigurations::from(&*SETTINGS);
        Ok(Json(config))
    }
}
