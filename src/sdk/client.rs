use crate::network::node::{Node, write_payload};
use std::{time::Duration};
use tokio::net::TcpStream;
use libp2p::{PeerId, noise};
use libp2p::core::{Multiaddr, identity};
use crate::network::node;
use tokio::sync::oneshot;
use snow::{Builder, TransportState};
use snow::params::NoiseParams;
use tokio::io;
use crate::network::protocols::ack_protocol::AckRequest;
use libp2p::swarm::NegotiatedSubstream;
use std::collections::HashMap;
use multihash::Code;
use bytes::BufMut;
use std::ops::DerefMut;
use crate::account::account_service::Account;
use async_trait::async_trait;
use log::info;
use crate::{request_proto, relay_proto, command_proto};
use multihash::MultihashDigest;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use crate::network::whitenoise_behaviour::{NodeAckRequest, NodeRequest};
use prost::Message;

#[async_trait]
pub trait SolanaClient {
    //Get nodes of the relay network
    async fn get_main_net_peers(&mut self, cnt: i32) -> Vec<PeerId>;
    //Register to a proxy node and start handle inbound circuits
    async fn register(&mut self, peer_id: PeerId) -> bool;
    //Dial a another client with whitenoise_id and build a secure circuit. Returns the session_id of this circuit.
    async fn dial(&mut self, remote_id: String) -> String;
    //Send message to a circuit of session_id.
    async fn send_message(&self, session_id: &str, data: &[u8]);
    //Get whitenoise_id of local client.
    fn get_whitenoise_id(&self) -> String;
}

#[derive(Clone)]
pub struct SecureConn {
    session_id: String,
    stream: std::sync::Arc<std::sync::Mutex<NegotiatedSubstream>>,
    noise: std::sync::Arc<std::sync::Mutex<TransportState>>,
}

pub struct WhiteNoiseClient {
    node: Node,
    new_client_timeout: Duration,
    bootstrap_addr: Multiaddr,
    bootstrap_peer_id: PeerId,
    sender_map: std::sync::Arc<std::sync::RwLock<HashMap<String, UnboundedSender<Vec<u8>>>>>,
    receiver_map: std::sync::Arc<std::sync::RwLock<HashMap<String, UnboundedReceiver<Vec<u8>>>>>,
}

impl WhiteNoiseClient {
    pub async fn init(bootstrap_addr_str: &str) -> Self {
        let parts: Vec<&str> = bootstrap_addr_str.split('/').collect();
        let bootstrap_peer_id_str = parts.get(parts.len() - 1).unwrap();
        info!("bootstrap peer id:{}", bootstrap_peer_id_str);
        let bootstrap_peer_id = PeerId::from_bytes(bs58::decode(bootstrap_peer_id_str).into_vec().unwrap().as_slice()).unwrap();
        let bootstrap_addr: Multiaddr = bootstrap_addr_str.parse().unwrap();

        let mut node = node::start().await;

        WhiteNoiseClient {
            node,
            new_client_timeout: Duration::from_secs(100),
            bootstrap_addr,
            bootstrap_peer_id,
            sender_map: std::sync::Arc::new(std::sync::RwLock::new(HashMap::new())),
            receiver_map: std::sync::Arc::new(std::sync::RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl SolanaClient for WhiteNoiseClient {
    async fn get_main_net_peers(&mut self, cnt: i32) -> Vec<PeerId> {
        let peer_list = self.node.get_main_nets(cnt, self.bootstrap_peer_id.clone(), self.bootstrap_addr.clone()).await;
        let mut peer_id_vec = Vec::with_capacity(peer_list.peers.len());
        peer_list.peers.iter().for_each(|x| {
            peer_id_vec.push(PeerId::from_bytes(bs58::decode(x.id.as_str()).into_vec().unwrap().as_slice()).unwrap());
        });
        return peer_id_vec;
    }

    async fn register(&mut self, peer_id: PeerId) -> bool {
        let ok = self.node.register_proxy(peer_id).await;
        if !ok {
            return false;
        }
        let mut node = self.node.clone();
        let receive_map = self.receiver_map.clone();
        //start answering dials
        tokio::spawn(async move {
            loop {
                let mut stream = node.wait_for_relay_stream().await;
                info!("received relay steam");
                let relay = loop {
                    let relay_inner = node::read_from_negotiated(&mut stream).await;
                    if relay_inner.r#type == relay_proto::Relaytype::SetSessionId as i32 {
                        break relay_inner;
                    }
                };

                info!("received relay setsession:{:?}", relay);
                let relay_set_session = relay_proto::SetSessionIdMsg::decode(relay.data.as_slice()).unwrap();
                info!("session role:{}", relay_set_session.role);
                let session_id = relay_set_session.session_id;
                let mut ack_msg = command_proto::Ack {
                    command_id: relay.id,
                    result: true,
                    data: Vec::new(),
                };
                let node_ack_request = NodeAckRequest {
                    remote_peer_id: node.proxy_id.clone().unwrap(),
                    ack_request: Some(AckRequest(ack_msg)),
                };
                let node_request = NodeRequest::AckRequest(node_ack_request);
                node.send_ack(node_request).await;

                let relay = loop {
                    let relay_inner = node::read_from_negotiated(&mut stream).await;
                    if relay_inner.r#type == relay_proto::Relaytype::Success as i32 {
                        break relay_inner;
                    }
                };
                info!("received relay handle success:{:?}", relay);

                let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
                    .into_authentic(&node.keypair)
                    .expect("Signing libp2p-noise static DH keypair failed.");

                let bb = noise_keys.public().as_ref();
                info!("noise pub key:{}", bs58::encode(bb).into_string());
                let msg = ["noise-libp2p-static-key:".as_bytes(), bb].concat();
                //
                let pp = noise_keys.clone().into_identity().public;
                let verify_succes = pp.verify(&msg, &noise_keys.clone().into_identity().signature.unwrap());
                info!("self verify success:{}", verify_succes);

                let params: NoiseParams = "Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap();
                let mut buf = vec![0u8; 65535];
                // Initialize our responder using a builder.
                let builder: Builder<'_> = Builder::new(params.clone());
                let mut noise =
                    builder.local_private_key(&noise_keys.secret().as_ref()).build_responder().unwrap();
                // <- e
                node::read_handshake_payload(&mut stream, &mut noise, &mut buf).await;

                // -> e, ee, s, es
                let payload = node::generate_handshake_payload(noise_keys.into_identity()).await;
                let len = noise.write_message(&payload, &mut buf).unwrap();
                node::write_handshake_payload(&mut stream, &buf[..len], len, &session_id).await;

                // <- s, se
                let len = node::read_handshake_payload(&mut stream, &mut noise, &mut buf).await;
                //verify

                let pubkey = noise.get_remote_static().unwrap();
                let verify_success = node::handle_remote_handshake_payload(&buf[..len], pubkey);
                info!("verify success:{}", verify_success);

                let mut noise = noise.into_transport_mode().unwrap();

                let (mut sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
                receive_map.write().unwrap().insert(session_id.to_string().clone(), receiver);

                tokio::spawn(async move {
                    let mut buf = [0u8; 65536];
                    loop {
                        let len = node::read_and_decrypt_payload(&mut stream, &mut noise, &mut buf).await;
                        let real_size = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                        info!("real size:{},buf len:{}", real_size, len);
                        let b2 = &buf[4..(real_size + 4)];
                        sender.send(Vec::from(b2));
                    }
                });
            }
        });
        ok
    }

    async fn dial(&mut self, remote_id: String) -> String {
        let public_key_secp256k1 = match self.node.keypair.public() {
            identity::PublicKey::Secp256k1(k) => k,
            _ => {
                panic!("key error");
            }
        };
        let local_whitenoise_id = bs58::encode(public_key_secp256k1.encode()).into_string();

        let session_id = generate_session_id(remote_id.clone(), local_whitenoise_id.clone());
        info!("session_id:{}", session_id);
        {
            let mut guard = self.node.circuit_task.write().unwrap();
            (*guard).insert(session_id.clone(), bs58::decode(remote_id.clone()).into_vec().unwrap());
        }

        if let Some(id) = self.node.proxy_id {
            self.node.new_relay_stream(id).await;
        } else {
            info!("not register to proxy yet");
            return "".to_string();
        }

        let mut stream = self.node.wait_for_relay_stream().await;
        info!("received relay steam");

        node::write_relay_wake(&mut stream).await;
        //set session id
        let key = node::write_set_session(&mut stream, session_id.clone()).await;
        let (s, r) = futures::channel::oneshot::channel();
        {
            let mut guard = self.node.event_bus.write().unwrap();
            (*guard).insert(key, s);
        }
        let ack_request = r.await.unwrap();
        let AckRequest(ack) = ack_request;
        info!("receive set session ack:{:?}", ack);

        node::new_circuit(remote_id, local_whitenoise_id, PeerId::from(self.node.keypair.public()).to_base58(), session_id.clone(), self.node.proxy_id.clone().unwrap(), self.node.event_bus.clone(), self.node.node_request_sender.clone()).await;

        loop {
            let relay = node::read_from_negotiated(&mut stream).await;

            if relay.r#type == (relay_proto::Relaytype::Success as i32) {
                info!("received relay success:{:?}", relay);
                break;
            }
        }

        let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
            .into_authentic(&self.node.keypair)
            .expect("Signing libp2p-noise static DH keypair failed.");

        let bb = noise_keys.public().as_ref();
        info!("noise pub key:{}", bs58::encode(bb).into_string());
        let msg = ["noise-libp2p-static-key:".as_bytes(), bb].concat();


        let params: NoiseParams = "Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap();
        let mut buf = vec![0u8; 65535];
        // Initialize our responder using a builder.
        let builder: Builder<'_> = Builder::new(params.clone());
        let mut noise =
            builder.local_private_key(&noise_keys.secret().as_ref()).build_initiator().unwrap();
        //write nil
        let len = noise.write_message(&[], &mut buf).unwrap();
        node::write_handshake_payload(&mut stream, &buf[..len], len, &session_id).await;
        info!("write nil");
        // <- s, se
        let len = node::read_handshake_payload(&mut stream, &mut noise, &mut buf).await;
        //verify
        info!("read identity");
        let pubkey = noise.get_remote_static().unwrap();
        let verify_success = node::handle_remote_handshake_payload(&buf[..len], pubkey);
        info!("verify success:{}", verify_success);


        // -> e, ee, s, es
        let payload = node::generate_handshake_payload(noise_keys.into_identity()).await;
        let len = noise.write_message(&payload, &mut buf).unwrap();
        node::write_handshake_payload(&mut stream, &buf[..len], len, &session_id).await;
        let mut noise = noise.into_transport_mode().unwrap();

        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        self.sender_map.write().unwrap().insert(session_id.clone(), sender);

        let session_id_clone = session_id.clone();
        tokio::spawn(async move {
            loop {
                let data: Vec<u8> = receiver.recv().await.unwrap();
                let mut buf = [0u8; 65536];
                let mut payload = Vec::new();
                payload.put_u32(data.len() as u32);
                payload.extend_from_slice(data.as_slice());
                let len = noise.write_message(payload.as_slice(), &mut buf).unwrap();
                let buf_tmp = &buf[..len];
                write_payload(&mut stream, buf_tmp, len, session_id_clone.as_str()).await;
            }
        });
        session_id
    }

    async fn send_message(&self, session_id: &str, data: &[u8]) {
        if let Some(sender) = self.sender_map.read().unwrap().get(session_id) {
            sender.send(data.to_vec());
        }
    }

    fn get_whitenoise_id(&self) -> String {
        Account::from_keypair_to_whitenoise_id(&self.node.keypair)
    }
}


pub fn generate_session_id(remote_id: String, local_id: String) -> String {
    let now = std::time::SystemTime::now();
    let time_bytes = &now.duration_since(std::time::UNIX_EPOCH).unwrap().as_micros().to_be_bytes()[8..];
    let to_hash = [local_id.as_bytes(), remote_id.as_bytes(), time_bytes].concat();
    let hash = &Code::Sha2_256.digest(&to_hash).to_bytes()[2..];
    bs58::encode(hash).into_string()
}