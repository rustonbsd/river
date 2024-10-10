
use std::str::FromStr;
use std::{
    net::SocketAddr,
    str::FromStr as _,
};

use base64::prelude::*;
use ini::Ini;
use once_cell::sync::Lazy;
use tokio::sync::OnceCell;
use anyhow::{bail, Error};
use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::sync::Mutex;

use crate::{config, TcpStream};
use crate::interface::Interface;
use crate::{interface::ToInterface as _, Config};


pub static WG_INTERFACE: Lazy<OnceCell<Mutex<Interface>>> =
    Lazy::new(|| OnceCell::new());

#[derive(Debug, Clone)]
pub struct WireGuardProxyConfig {
    pub private_key: [u8; 32],
    pub address: String,
    pub public_key: [u8; 32],
    pub endpoint: String,
}

impl WireGuardProxyConfig {
    fn parse(wg_conf: &ConfigWireGuard) -> anyhow::Result<Self> {
        let wg_peer = match wg_conf.peers.first() {
            Some(wg_peer) => wg_peer,
            None => anyhow::bail!("wireguard peer missing"),
        };

        Ok(WireGuardProxyConfig {
            private_key: wg_conf.private_key,
            address: match wg_conf.address.first() {
                Some(address) => address.clone(),
                None => anyhow::bail!("wireguard address missing"),
            },
            public_key: wg_peer.public_key.clone(),
            endpoint: wg_peer.endpoint.clone(),
        })
    }

    pub async fn connect_addr(&self, addr: SocketAddr) -> anyhow::Result<TcpStream, anyhow::Error> {
        let config = Config {
            interface: config::Interface {
                private_key: StaticSecret::from(self.private_key),
                // Our address on the WireGuard network
                address: config::Address::from_str(&self.address).unwrap(),
                // Let the interface pick a random port
                listen_port: None,
                // Let the interface pick an appropriate MTU
                mtu: None,
            },
            peers: vec![config::Peer {
                public_key: PublicKey::from(self.public_key),
                // This is where the tunneled WireGuard traffic will be sent
                endpoint: Some(self.endpoint.clone().parse().unwrap()),
                // IP addresses the peer can handle traffic to and from on the WireGuard network
                // The /32 suffix indicates that the peer only handles traffic for itself
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                // Send a keepalive packet every 15 seconds
                persistent_keepalive: Some(15),
            }],
        };
        let interface = get_or_init_wg_interface(config).await.unwrap();
        let cloned_interface = interface.lock().await.clone();
        match TcpStream::connect(addr, cloned_interface).await {
            Ok(con) => Ok(con),
            Err(_) => bail!("failed to create tcp stream over wireguard"),
        }
    }
}

impl FromStr for WireGuardProxyConfig {

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match ConfigWireGuard::from_str(&s) {
            Ok(config) => Self::parse(&config),
            Err(_) => bail!("failed to parse wireguard configuration: {:?}", &s),
        }
    }
    
    type Err = anyhow::Error;
}

#[derive(Debug)]
pub(crate) struct ConfigWireguardPeer {
    pub public_key: [u8; 32],
    pub allowed_ips: Vec<String>,
    pub endpoint: String,
    pub persistent_keepalive: Option<u16>,
}

#[derive(Debug)]
pub(crate) struct ConfigWireGuard {
    pub private_key: [u8; 32],
    pub address: Vec<String>,
    pub listen_port: Option<u16>,
    pub peers: Vec<ConfigWireguardPeer>,
}

async fn get_or_init_wg_interface(
    config: Config,
) -> Result<&'static Mutex<Interface>,Error> {
    Ok(WG_INTERFACE
        .get_or_init(|| async {
            println!("Wireguard interface created!");
            Mutex::new(
                config
                    .to_interface()
                    .await
                    .expect("Failed to initialize wireguard interface "))
        })
        .await)
}

impl ConfigWireGuard {
    pub fn from_str(wireguard_config_str: &str) -> anyhow::Result<Self, anyhow::Error> {
        let conf = match Ini::load_from_str(wireguard_config_str) {
            Ok(conf) => conf,
            Err(_) => anyhow::bail!("failed to load wireguard config from string"),
        };

        // Parse Interface section
        let interface = match conf.section(Some("Interface")) {
            Some(interface) => interface,
            None => anyhow::bail!("Missing Interface section"),
        };

        let private_key = match interface.get("PrivateKey") {
            Some(private_key) => {
                let mut pk_bytes: [u8; 32] = [0u8; 32];
                BASE64_STANDARD
                    .decode_slice(private_key, &mut pk_bytes)
                    .unwrap();
                pk_bytes
            }
            None => anyhow::bail!("Missing PrivateKey"),
        };

        let address = match interface.get("Address") {
            Some(addrs) => addrs.split(',').map(|s| s.trim().to_string()).collect(),
            None => anyhow::bail!("Missing Address"),
        };

        let listen_port = match interface
            .get("ListenPort")
            .map(|p| p.parse::<u16>())
            .transpose()
        {
            Ok(listen_port) => listen_port,
            Err(_) => None,
        };

        // Parse Peer sections
        let mut peers = Vec::new();
        for (section_name, section) in conf.iter() {
            if section_name.map_or(false, |name| name.starts_with("Peer")) {
                let peer = ConfigWireguardPeer {
                    public_key: match section.get("PublicKey") {
                        Some(public_key) => {
                            let mut pk_slice: [u8; 32] = [0u8; 32];
                            BASE64_STANDARD
                                .decode_slice(public_key, &mut pk_slice)
                                .unwrap();
                            pk_slice
                        }
                        None => anyhow::bail!("Missing PublicKey in Peer"),
                    },
                    allowed_ips: match section.get("AllowedIPs") {
                        Some(allowed_ips) => allowed_ips
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .collect::<Vec<String>>(),
                        None => anyhow::bail!("Missing AllowedIPs in Peer"),
                    },
                    endpoint: match section.get("Endpoint").map(String::from) {
                        Some(endpoint) => endpoint,
                        None => anyhow::bail!("Missing Endpoint in Peer"),
                    },
                    persistent_keepalive: section
                        .get("PersistentKeepalive")
                        .map(|v| v.parse::<u16>())
                        .transpose()?,
                };
                peers.push(peer);
            }
        }

        Ok(ConfigWireGuard {
            private_key,
            address,
            listen_port,
            peers,
        })
    }
}
