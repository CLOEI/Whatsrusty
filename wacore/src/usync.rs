use anyhow::{Result, anyhow};
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{Jid, LEGACY_USER_SERVER};
use wacore_binary::node::Node;
use crate::types::user::{IsOnWhatsAppResponse, VerifiedName};
use waproto::whatsapp as wa;
use prost::Message;

pub fn build_get_user_devices_query(jids: &[Jid], sid: &str) -> Node {
    let user_nodes = jids
        .iter()
        .map(|jid| {
            NodeBuilder::new("user")
                .attr("jid", jid.to_non_ad().to_string())
                .build()
        })
        .collect::<Vec<_>>();

    let query_node = NodeBuilder::new("query")
        .children([NodeBuilder::new("devices").attr("version", "2").build()])
        .build();

    let list_node = NodeBuilder::new("list").children(user_nodes).build();

    NodeBuilder::new("usync")
        .attrs([
            ("context", "message"),
            ("index", "0"),
            ("last", "true"),
            ("mode", "query"),
            ("sid", sid),
        ])
        .children([query_node, list_node])
        .build()
}

pub fn parse_get_user_devices_response(resp_node: &Node) -> Result<Vec<Jid>> {
    let list_node = resp_node
        .get_optional_child_by_tag(&["usync", "list"])
        .ok_or_else(|| anyhow!("<usync> or <list> not found in usync response"))?;

    let mut all_devices = Vec::new();

    for user_node in list_node.get_children_by_tag("user") {
        let user_jid = user_node.attrs().jid("jid");
        let device_list_node = user_node
            .get_optional_child_by_tag(&["devices", "device-list"])
            .ok_or_else(|| anyhow!("<device-list> not found for user {user_jid}"))?;

        for device_node in device_list_node.get_children_by_tag("device") {
            let device_id_str = device_node.attrs().string("id");
            let device_id: u16 = device_id_str.parse()?;

            let mut device_jid = user_jid.clone();
            device_jid.device = device_id;
            all_devices.push(device_jid);
        }
    }

    Ok(all_devices)
}

pub fn build_is_on_whatsapp_query(phone_numbers: &[String], sid: &str) -> Node {
    let user_nodes = phone_numbers
        .iter()
        .map(|phone| {
            let jid = Jid::new(phone, LEGACY_USER_SERVER);
            NodeBuilder::new("user")
                .children([
                    NodeBuilder::new("contact")
                        .bytes(jid.to_string().into_bytes())
                        .build()
                ])
                .build()
        })
        .collect::<Vec<_>>();

    let query_node = NodeBuilder::new("query")
        .children([
            NodeBuilder::new("business")
                .children([NodeBuilder::new("verified_name").build()])
                .build(),
            NodeBuilder::new("contact").build(),
        ])
        .build();

    let list_node = NodeBuilder::new("list").children(user_nodes).build();

    NodeBuilder::new("usync")
        .attrs([
            ("context", "interactive"),
            ("index", "0"),
            ("last", "true"),
            ("mode", "query"),
            ("sid", sid),
        ])
        .children([query_node, list_node])
        .build()
}

fn parse_verified_name(business_node: Option<&Node>) -> Result<Option<VerifiedName>> {
    let business_node = match business_node {
        Some(node) if node.tag == "business" => node,
        _ => return Ok(None),
    };

    let verified_name_node = match business_node.get_optional_child_by_tag(&["verified_name"]) {
        Some(node) => node,
        None => return Ok(None),
    };

    let raw_cert = match &verified_name_node.content {
        Some(wacore_binary::node::NodeContent::Bytes(bytes)) => bytes,
        _ => return Ok(None),
    };

    let certificate = wa::VerifiedNameCertificate::decode(&raw_cert[..])?;

    let details_bytes = certificate.details.as_ref()
        .ok_or_else(|| anyhow!("No details in verified name certificate"))?;

    let details = wa::verified_name_certificate::Details::decode(&details_bytes[..])?;

    Ok(Some(VerifiedName {
        certificate: Box::new(certificate),
        details: Box::new(details),
    }))
}

pub fn parse_is_on_whatsapp_response(resp_node: &Node) -> Result<Vec<IsOnWhatsAppResponse>> {
    let list_node = resp_node
        .get_optional_child_by_tag(&["usync", "list"])
        .ok_or_else(|| anyhow!("<usync> or <list> not found in IsOnWhatsApp response"))?;

    let mut responses = Vec::new();
    let query_suffix = format!("@{}", LEGACY_USER_SERVER);

    for user_node in list_node.get_children_by_tag("user") {
        if user_node.tag != "user" {
            continue;
        }

        let mut attr_parser = user_node.attrs();
        let jid_str = attr_parser.string("jid");
        let jid = match jid_str.parse::<Jid>() {
            Ok(jid) => jid,
            Err(_) => continue,
        };

        let business_node = user_node.get_optional_child_by_tag(&["business"]);
        let verified_name = parse_verified_name(business_node)?;

        let contact_node = user_node.get_optional_child_by_tag(&["contact"]);
        let is_in = contact_node
            .map(|node| {
                let mut contact_attrs = node.attrs();
                contact_attrs.optional_string("type").unwrap_or("") == "in"
            })
            .unwrap_or(false);

        let query = contact_node
            .and_then(|node| match &node.content {
                Some(wacore_binary::node::NodeContent::Bytes(bytes)) => {
                    String::from_utf8(bytes.to_vec()).ok()
                },
                _ => None,
            })
            .map(|query_str| {
                if query_str.ends_with(&query_suffix) {
                    query_str[..query_str.len() - query_suffix.len()].to_string()
                } else {
                    query_str
                }
            })
            .unwrap_or_default();

        responses.push(IsOnWhatsAppResponse {
            query,
            jid,
            is_in,
            verified_name,
        });
    }

    Ok(responses)
}
