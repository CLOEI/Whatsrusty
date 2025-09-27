use super::traits::StanzaHandler;
use crate::client::Client;
use crate::types::events::Event;
use async_trait::async_trait;
use log::{info, warn};
use std::sync::Arc;
use wacore_binary::{jid::SERVER_JID, node::Node};

/// Handler for `<notification>` stanzas.
///
/// Processes various notification types including:
/// - Encrypt notifications (key upload requests)
/// - Server sync notifications
/// - Account sync notifications (push name updates)
#[derive(Default)]
pub struct NotificationHandler;

impl NotificationHandler {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl StanzaHandler for NotificationHandler {
    fn tag(&self) -> &'static str {
        "notification"
    }

    async fn handle(&self, client: Arc<Client>, node: &Node, _cancelled: &mut bool) -> bool {
        handle_notification_impl(&client, node).await;
        true
    }
}

async fn handle_notification_impl(client: &Arc<Client>, node: &Node) {
    let notification_type = node.attrs.get("type").cloned().unwrap_or_default();

    match notification_type.as_str() {
        "encrypt" => {
            if let Some(from) = node.attrs.get("from")
                && from == SERVER_JID
            {
                let client_clone = client.clone();
                tokio::spawn(async move {
                    if let Err(e) = client_clone.upload_pre_keys().await {
                        warn!("Failed to upload pre-keys after notification: {:?}", e);
                    }
                });
            }
        }
        "server_sync" => {
            info!(target: "Client", "Received `server_sync` notification, scheduling app state sync(s).");
            for collection_node in node.get_children_by_tag("collection") {
                let name = collection_node
                    .attrs
                    .get("name")
                    .cloned()
                    .unwrap_or_default();
                let version = collection_node
                    .attrs
                    .get("version")
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
                info!(
                    target: "Client/AppState",
                    "scheduling sync for collection '{name}' from version {version}."
                );
            }
        }
        "account_sync" => {
            if let Some(push_name_attr) = node.attrs.get("pushname") {
                let new_push_name = push_name_attr.clone();
                client
                    .clone()
                    .update_push_name_and_notify(new_push_name)
                    .await;
            } else {
                warn!(target: "Client", "TODO: Implement full handler for <notification type='account_sync'>, for now dispatching generic event.");
                client
                    .core
                    .event_bus
                    .dispatch(&Event::Notification(node.clone()));
            }
        }
        "link_code_companion_reg" => {
            info!(target: "Client/PhonePair", "Received phone pairing notification with correct type");
            handle_code_pair_notification(client, node).await;
        }
        _ => {
            warn!(target: "Client", "TODO: Implement handler for <notification type='{notification_type}'>");
            client
                .core
                .event_bus
                .dispatch(&Event::Notification(node.clone()));
        }
    }
}

/// Handles the code pair notification when the user enters the pairing code on their phone.
///
/// This implements the cryptographic exchange that happens when a user enters the 8-digit
/// pairing code on their phone to link the companion device.
async fn handle_code_pair_notification(client: &Arc<Client>, parent_node: &Node) {
    use wacore::phone_pair::*;
    use wacore_binary::node::NodeContent;
    use wacore_binary::builder::NodeBuilder;
    use wacore_binary::jid::SERVER_JID;
    use log::{error, info};

    // Find the link_code_companion_reg node inside the notification
    let node = match parent_node.get_optional_child("link_code_companion_reg") {
        Some(node) => node,
        None => {
            error!(target: "Client/PhonePair", "Missing link_code_companion_reg element in notification");
            return;
        }
    };

    // Get the phone linking cache - this must exist for pairing to work
    let link_cache = match client.phone_linking_cache.lock().await.take() {
        Some(cache) => cache,
        None => {
            error!(target: "Client/PhonePair", "Received code pair notification without a pending pairing");
            return;
        }
    };

    // Extract pairing reference and validate it matches our cache
    let link_code_pairing_ref = match node
        .get_optional_child("link_code_pairing_ref")
        .and_then(|n| n.content.as_ref())
    {
        Some(NodeContent::Bytes(bytes)) => bytes,
        _ => {
            error!(target: "Client/PhonePair", "Missing link_code_pairing_ref element");
            return;
        }
    };

    let pairing_ref_str = match String::from_utf8(link_code_pairing_ref.clone()) {
        Ok(s) => s,
        Err(_) => {
            error!(target: "Client/PhonePair", "Invalid UTF-8 in pairing reference");
            return;
        }
    };

    if pairing_ref_str != link_cache.pairing_ref {
        error!(target: "Client/PhonePair", "Pairing ref mismatch in code pair notification");
        return;
    }

    // Extract wrapped primary ephemeral public key
    let wrapped_primary_ephemeral_pub = match node
        .get_optional_child("link_code_pairing_wrapped_primary_ephemeral_pub")
        .and_then(|n| n.content.as_ref())
    {
        Some(NodeContent::Bytes(bytes)) => bytes,
        _ => {
            error!(target: "Client/PhonePair", "Missing link_code_pairing_wrapped_primary_ephemeral_pub element");
            return;
        }
    };

    // Extract primary identity public key
    let primary_identity_pub = match node
        .get_optional_child("primary_identity_pub")
        .and_then(|n| n.content.as_ref())
    {
        Some(NodeContent::Bytes(bytes)) => bytes,
        _ => {
            error!(target: "Client/PhonePair", "Missing primary_identity_pub element");
            return;
        }
    };

    // Generate random bytes for adv secret computation
    let mut adv_secret_random = [0u8; 32];
    use rand::{rng, RngCore};
    rng().fill_bytes(&mut adv_secret_random);

    // Decrypt the primary device's ephemeral public key
    let primary_decrypted_pubkey = match decrypt_primary_ephemeral_key(
        &link_cache.linking_code,
        wrapped_primary_ephemeral_pub,
    ) {
        Ok(key) => key,
        Err(e) => {
            error!(target: "Client/PhonePair", "Failed to decrypt primary ephemeral key: {e}");
            return;
        }
    };

    // Compute the ephemeral shared secret using our ephemeral private key and the decrypted primary ephemeral public key
    let ephemeral_shared_secret = match link_cache.key_pair.private_key.calculate_agreement(
        &match wacore::libsignal::protocol::PublicKey::from_djb_public_key_bytes(&primary_decrypted_pubkey) {
            Ok(pk) => pk,
            Err(e) => {
                error!(target: "Client/PhonePair", "Failed to parse primary decrypted public key: {e}");
                return;
            }
        }
    ) {
        Ok(secret) => secret,
        Err(e) => {
            error!(target: "Client/PhonePair", "Failed to compute ephemeral shared secret: {e}");
            return;
        }
    };

    // Get our identity key for the key bundle
    let device_snapshot = client.persistence_manager.get_device_snapshot().await;
    let identity_key_bytes = device_snapshot.identity_key.public_key.public_key_bytes();

    // Encrypt and wrap the key bundle containing our identity key, primary identity key, and randomness
    let wrapped_key_bundle = match encrypt_key_bundle(
        &ephemeral_shared_secret,
        identity_key_bytes,
        primary_identity_pub,
        &adv_secret_random,
    ) {
        Ok(bundle) => bundle,
        Err(e) => {
            error!(target: "Client/PhonePair", "Failed to encrypt key bundle: {e}");
            return;
        }
    };

    // Compute the identity shared secret for adv secret computation
    let primary_identity_pubkey = match wacore::libsignal::protocol::PublicKey::from_djb_public_key_bytes(primary_identity_pub) {
        Ok(pk) => pk,
        Err(e) => {
            error!(target: "Client/PhonePair", "Failed to parse primary identity public key: {e}");
            return;
        }
    };

    let identity_shared_key = match device_snapshot.identity_key.private_key.calculate_agreement(&primary_identity_pubkey) {
        Ok(secret) => secret,
        Err(e) => {
            error!(target: "Client/PhonePair", "Failed to compute identity shared key: {e}");
            return;
        }
    };

    // Compute the adv secret (used to authenticate pair-success event later)
    let adv_secret = match compute_adv_secret(
        &ephemeral_shared_secret,
        &identity_shared_key,
        &adv_secret_random,
    ) {
        Ok(secret) => secret,
        Err(e) => {
            error!(target: "Client/PhonePair", "Failed to compute adv secret: {e}");
            return;
        }
    };

    // Store the adv secret key for later use in pair-success authentication
    client
        .persistence_manager
        .process_command(crate::store::commands::DeviceCommand::SetAdvSecretKey(adv_secret))
        .await;

    // Build and send the companion_finish response
    let finish_node = NodeBuilder::new("link_code_companion_reg")
        .attrs([
            ("jid", link_cache.jid.to_string()),
            ("stage", "companion_finish".to_string()),
        ])
        .children([
            NodeBuilder::new("link_code_pairing_wrapped_key_bundle")
                .bytes(wrapped_key_bundle)
                .build(),
            NodeBuilder::new("companion_identity_public")
                .bytes(identity_key_bytes.to_vec())
                .build(),
            NodeBuilder::new("link_code_pairing_ref")
                .bytes(link_code_pairing_ref.clone())
                .build(),
        ])
        .build();

    let iq = crate::request::InfoQuery {
        namespace: "md",
        query_type: crate::request::InfoQueryType::Set,
        to: SERVER_JID.parse().unwrap(),
        target: None,
        id: None,
        content: Some(wacore_binary::node::NodeContent::Nodes(vec![finish_node])),
        timeout: None,
    };

    let client_clone = client.clone();
    tokio::spawn(async move {
        match client_clone.send_iq(iq).await {
            Ok(_response) => {
                info!(target: "Client/PhonePair", "Phone pairing companion_finish completed successfully");
            }
            Err(e) => {
                error!(target: "Client/PhonePair", "Failed to complete companion_finish: {e}");
            }
        }
    });
}
