use async_trait::async_trait;

use libp2p::{
    noise::{NoiseConfig, X25519Spec, Keypair},
    identify, NetworkBehaviour, swarm::{NetworkBehaviourEventProcess, SwarmBuilder},
    request_response::{RequestResponseMessage, ProtocolSupport, RequestResponseEvent, RequestResponseConfig, RequestResponse, RequestResponseCodec, ProtocolName},
    Swarm,
    Multiaddr, PeerId,
    Transport,
    core::upgrade::{self, read_one, write_one, write_with_len_prefix},
    identity,
    mplex,
    tcp::TokioTcpConfig,
    swarm::NegotiatedSubstream,
    noise::KeypairIdentity,
};
use whitenoise_behaviour::AddPeerAddresses;
use crate::{command_proto, payload_proto, relay_proto, request_proto, chat_proto, gossip_proto};
use futures::{prelude::*, channel::oneshot};
use rand::{self, Rng};
use std::{iter, ops::Mul};
use std::error::Error;
use tokio::io::{self, AsyncBufReadExt};
use prost::Message;
use multihash::{Code, MultihashDigest};
use tokio::sync::mpsc;
use log::info;
use super::{whitenoise_behaviour::WhitenoiseBehaviour};
use super::protocols::proxy_protocol::{ProxyCodec, ProxyRequest, ProxyResponse, ProxyProtocol};
use super::protocols::ack_protocol::{AckCodec, AckRequest, AckResponse, AckProtocol};
use super::protocols::relay_behaviour;

use libp2p::{identity::PublicKey::Secp256k1};
use rusty_leveldb::{DB, DBIterator, LdbIterator, Options};

use std::collections::VecDeque;

use eth_ecies::{Secret, brain, Public};
use eth_ecies::Generator;
use eth_ecies::crypto::ecies;
use bytes::BufMut;
use snow::{params::NoiseParams, Builder, HandshakeState, TransportState};
use crate::account::account_service;
use super::whitenoise_behaviour::{self, NodeRequest, NodeNewStream, NodeProxyRequest, NodeAckRequest};
use tokio::sync::mpsc::{UnboundedReceiver};
use crate::account::account_service::Account;
use std::collections::HashMap;
use tokio::sync::mpsc::{UnboundedSender};
use std::io::stderr;

pub enum SessionRole {
    CallerRole = 1,
    EntryRole,
    JointRole,
    RelayRole,
    ExitRole,
    AnswerRole,
}

#[derive(Clone)]
pub struct Node {
    pub node_request_sender: mpsc::UnboundedSender<NodeRequest>,
    pub event_bus: std::sync::Arc<std::sync::RwLock<std::collections::HashMap<String, oneshot::Sender<AckRequest>>>>,
    pub keypair: libp2p::identity::Keypair,
    pub proxy_id: Option<PeerId>,
    pub inbound_relay_streams: std::sync::Arc<std::sync::RwLock<VecDeque<NegotiatedSubstream>>>,
    pub outbound_relay_streams: std::sync::Arc<std::sync::RwLock<VecDeque<NegotiatedSubstream>>>,
    pub circuit_task: std::sync::Arc<std::sync::RwLock<std::collections::HashMap<String, Vec<u8>>>>,
}

pub async fn external_send_node_request_and_wait(event_bus: std::sync::Arc<std::sync::RwLock<HashMap<String, oneshot::Sender<AckRequest>>>>, node_request_sender: UnboundedSender<NodeRequest>, key: String, node_request: NodeRequest) -> AckRequest {
    let (ack_request_sender, ack_request_receiver) = oneshot::channel();
    {
        let mut guard = event_bus.write().unwrap();
        (*guard).insert(key, ack_request_sender);
    }
    node_request_sender.send(node_request);
    ack_request_receiver.await.unwrap()
}

impl Node {
    //without timeout
    pub async fn get_main_nets(&mut self, cnt: i32, remote_peer_id: PeerId, remote_peer_addr: Multiaddr) -> request_proto::PeersList {
        let mut remote_peer_addr_smallvec = smallvec::SmallVec::<[Multiaddr; 6]>::new();
        remote_peer_addr_smallvec.push(remote_peer_addr.clone());
        let add_peer_addresses = AddPeerAddresses {
            remote_peer_id: remote_peer_id.clone(),
            remote_addr: remote_peer_addr_smallvec,
        };
        self.node_request_sender.send(NodeRequest::AddPeerAddressesRequest(add_peer_addresses));
        //wait address insert to position
        std::thread::sleep(std::time::Duration::from_millis(20));

        //generate request for mainnet peers
        let mainnets = request_proto::MainNetPeers {
            max: cnt
        };
        let mut buf_for_main = Vec::new();
        let data = mainnets.encode(&mut buf_for_main);
        let mut request = request_proto::Request {
            data: buf_for_main,
            req_id: String::from(""),
            from: String::from(""),
            reqtype: request_proto::Reqtype::MainNetPeers as i32,
        };

        let key = from_request_get_id(&request);
        request.req_id = key.clone();

        let proxy_request = ProxyRequest(request.clone());
        let node_proxy_request_get_mainnets = NodeProxyRequest {
            remote_peer_id: remote_peer_id.clone(),
            proxy_request: Some(proxy_request),
        };
        let AckRequest(data) = external_send_node_request_and_wait(self.event_bus.clone(), self.node_request_sender.clone(), key, NodeRequest::ProxyRequest(node_proxy_request_get_mainnets)).await;

        info!("finished get mainnets this turn:{}", data.command_id);
        let peer_list = request_proto::PeersList::decode(data.data.as_slice()).unwrap();
        for peer in peer_list.peers.clone() {
            let mut addr_smallvec = smallvec::SmallVec::<[Multiaddr; 6]>::new();
            peer.addr.iter().for_each(|x| addr_smallvec.push(x.clone().parse().unwrap()));
            let add_addresses_after_getmainnets = AddPeerAddresses {
                remote_peer_id: PeerId::from_bytes(bs58::decode(peer.id).into_vec().unwrap().as_slice()).unwrap(),
                remote_addr: addr_smallvec,
            };
            info!("register:{:?},peer_id:{:?}", add_addresses_after_getmainnets.remote_addr, add_addresses_after_getmainnets.remote_peer_id);
            self.node_request_sender.send(NodeRequest::AddPeerAddressesRequest(add_addresses_after_getmainnets));
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
        return peer_list;
    }

    pub async fn send_ack(&mut self, ack_request: NodeRequest) {
        self.node_request_sender.send(ack_request);
    }


    pub async fn register_proxy(&mut self, remote_peer_id: PeerId) -> std::io::Result<()> {
        let new_proxy = request_proto::NewProxy {
            time: String::from("60m"),
            white_noise_id: Account::from_keypair_to_whitenoise_id(&self.keypair),
        };
        info!("local whitenoise id:{}", new_proxy.white_noise_id);
        let mut data_buf = Vec::new();
        new_proxy.encode(&mut data_buf);
        let local_peer_id = PeerId::from(self.keypair.public());
        info!("local peer id:{}", local_peer_id.to_base58());
        let mut request = request_proto::Request {
            data: data_buf,
            req_id: String::from(""),
            from: local_peer_id.to_base58(),
            reqtype: request_proto::Reqtype::NewProxy as i32,
        };

        let key = from_request_get_id(&request);
        request.req_id = key.clone();
        let proxy_request = ProxyRequest(request);

        let node_proxy_request = NodeProxyRequest {
            remote_peer_id: remote_peer_id.clone(),
            proxy_request: Some(proxy_request),
        };
        let AckRequest(ack) = external_send_node_request_and_wait(self.event_bus.clone(), self.node_request_sender.clone(), key, NodeRequest::ProxyRequest(node_proxy_request)).await;
        info!("finished register proxy this turn:{}", ack.command_id);
        if ack.result {
            self.proxy_id = Some(remote_peer_id);
            return Ok(());
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                std::str::from_utf8(ack.data.as_slice()).unwrap_or("register proxy failed"),
            ));
        }
    }

    pub async fn wait_for_outbound_relay_stream(&mut self) -> NegotiatedSubstream {
        loop {
            let mut guard = self.outbound_relay_streams.write().unwrap();
            let mut relay_stream_option = (*guard).pop_front();
            if relay_stream_option.is_some() {
                return relay_stream_option.unwrap();
            } else {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
    }

    pub async fn wait_for_inbound_relay_stream(&mut self) -> NegotiatedSubstream {
        loop {
            let mut guard = self.inbound_relay_streams.write().unwrap();
            let mut relay_stream_option = (*guard).pop_front();
            if relay_stream_option.is_some() {
                return relay_stream_option.unwrap();
            } else {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
    }


    pub async fn new_relay_stream(&mut self, peer_id: PeerId) {
        let node_new_stream = NodeNewStream { peer_id: peer_id };
        let node_request = NodeRequest::NewStreamRequest(node_new_stream);
        self.node_request_sender.send(node_request);
    }
}

pub async fn process_proxy_request(mut proxy_request_receiver: UnboundedReceiver<NodeProxyRequest>, node: Node) {
    let secret_key = Account::from_keypair_to_secretkey_bytes(&node.keypair);
    let secret = Secret::from_slice(&secret_key).unwrap();
    loop {
        let proxy_request_option = proxy_request_receiver.recv().await;
        if proxy_request_option.is_some() {
            let node_proxy_request = proxy_request_option.unwrap();
            let ProxyRequest(request) = node_proxy_request.proxy_request.clone().unwrap();
            if request.reqtype == (request_proto::Reqtype::DecryptGossip as i32) {
                let mut ack_response = command_proto::Ack { command_id: request.req_id, result: false, data: Vec::new() };

                let decrypt = request_proto::Decrypt::decode(request.data.as_slice()).unwrap();
                let decrypt_res = ecies::decrypt(&secret, b"", &decrypt.cypher);

                if decrypt_res.is_ok() {
                    let plain_text = decrypt_res.unwrap();
                    let neg = gossip_proto::Negotiate::decode(plain_text.as_slice()).unwrap();
                    info!("neg:{:?}", neg);
                    ack_response.result = true;
                    ack_response.data = plain_text;
                    let ack_request = AckRequest(ack_response);
                    let node_ack_request = NodeAckRequest {
                        remote_peer_id: node_proxy_request.remote_peer_id,
                        ack_request: Some(ack_request),
                    };
                    node.node_request_sender.send(NodeRequest::AckRequest(node_ack_request));
                } else {
                    decrypt_res.unwrap();
                }
            } else if request.reqtype == (request_proto::Reqtype::NegPlainText as i32) {
                info!("receive encrypt request");
                let mut ack_response = command_proto::Ack { command_id: request.req_id, result: false, data: Vec::new() };

                let neg_plaintext = request_proto::NegPlaintext::decode(request.data.as_slice()).unwrap();
                let guard = node.circuit_task.write().unwrap();
                let pub_bytes = (*guard).get(&neg_plaintext.session_id).unwrap();

                let secp_pub_key = identity::secp256k1::PublicKey::decode(pub_bytes).unwrap();
                let serialized = secp_pub_key.encode_uncompressed();

                let mut public_key = Public::default();
                public_key.copy_from_slice(&serialized[1..65]);

                let crypted_text = ecies::encrypt(&public_key, b"", &neg_plaintext.neg).unwrap();
                ack_response.result = true;
                ack_response.data = crypted_text;
                let ack_request = AckRequest(ack_response);
                let node_ack_request = NodeAckRequest {
                    remote_peer_id: node_proxy_request.remote_peer_id,
                    ack_request: Some(ack_request),
                };
                node.node_request_sender.send(NodeRequest::AckRequest(node_ack_request));
                info!("send encrypt neg");
            }
        }
    }
}


pub async fn start() -> Node {
    let (node_request_sender, mut node_request_receiver) = mpsc::unbounded_channel();
    let id_keys = account_service::Account::get_default_account_keypair("./db");
    let peer_id = id_keys.public().into_peer_id();
    info!("local peer id is {:?}", peer_id);

    let noise_keys = Keypair::<X25519Spec>::new().into_authentic(&id_keys).unwrap();
    let trans = TokioTcpConfig::new()
        .nodelay(true)
        .upgrade(upgrade::Version::V1)
        .authenticate(NoiseConfig::xx(noise_keys).into_authenticated())
        .multiplex(mplex::MplexConfig::default())
        .timeout(std::time::Duration::from_secs(2))
        .boxed();


    let proxy_protocols = iter::once((ProxyProtocol(), ProtocolSupport::Full));
    let mut proxy_cfg = RequestResponseConfig::default();
    let proxy_behaviour = RequestResponse::new(ProxyCodec(), proxy_protocols, proxy_cfg);


    let ack_protocols = iter::once((AckProtocol(), ProtocolSupport::Full));
    let mut ack_cfg = RequestResponseConfig::default();
    let ack_behaviour = RequestResponse::new(AckCodec(), ack_protocols, ack_cfg);

    let identify_behaviour = identify::Identify::new(String::from("/ipfs/id/1.0.0"), format!("rust-libp2p/{}", env!("CARGO_PKG_VERSION")), id_keys.public());

    let relay_behaviour = relay_behaviour::Relay { events: std::collections::VecDeque::new(), addresses: std::collections::HashMap::new() };

    let event_bus = std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));

    let inbound_relay_streams = std::sync::Arc::new(std::sync::RwLock::new(std::collections::VecDeque::new()));

    let outbound_relay_streams = std::sync::Arc::new(std::sync::RwLock::new(std::collections::VecDeque::new()));

    let (mut proxy_request_sender, mut proxy_request_receiver) = mpsc::unbounded_channel();

    let mut whitenoise_behaviour = WhitenoiseBehaviour {
        proxy_behaviour: proxy_behaviour,
        ack_behaviour: ack_behaviour,
        identify_behaviour: identify_behaviour,
        event_bus: event_bus.clone(),
        inbound_relay_streams: inbound_relay_streams.clone(),
        outbound_relay_streams: outbound_relay_streams.clone(),
        relay_behaviour: relay_behaviour,
        proxy_request_channel: proxy_request_sender,
    };

    let node = Node {
        node_request_sender: node_request_sender.clone(),
        event_bus: event_bus.clone(),
        keypair: id_keys,
        proxy_id: None,
        inbound_relay_streams: inbound_relay_streams.clone(),
        outbound_relay_streams: outbound_relay_streams.clone(),
        circuit_task: std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
    };


    let mut swarm1 = SwarmBuilder::new(trans, whitenoise_behaviour, peer_id)
        .executor(Box::new(|fut| {
            tokio::spawn(fut);
        }))
        .build();

    tokio::spawn(whitenoise_behaviour::whitenoise_event_loop(swarm1, node_request_receiver));
    let node_work = node.clone();

    tokio::spawn(process_proxy_request(proxy_request_receiver, node.clone()));
    return node;
}

pub fn from_request_get_id(request: &request_proto::Request) -> String {
    let mut buf = Vec::new();
    request.encode(&mut buf).unwrap();
    from_bytes_get_id(&buf)
}

pub fn from_bytes_get_id(buf: &[u8]) -> String {
    let hash_algorithm = Code::Sha2_256;
    let hash = hash_algorithm.digest(buf);
    //remove code and slice
    let hash_bytes = hash.to_bytes()[2..].to_vec();
    bs58::encode(hash_bytes).into_string()
}


pub fn from_whitenoise_to_hash(whitenoise_id: String) -> String {
    let whitenoise_bytes = bs58::decode(whitenoise_id).into_vec().unwrap();
    let hash_algorithm = Code::Sha2_256;
    let hash = hash_algorithm.digest(&whitenoise_bytes);
    //remove code and slice
    let zz = hash.to_bytes()[2..].to_vec();
    bs58::encode(zz.as_slice()).into_string()
}

pub fn handle_remote_handshake_payload(payload: &[u8], remote_static: &[u8]) -> bool {
    let noise_shakehand_payload = payload_proto::NoiseHandshakePayload::decode(payload).unwrap();

    let id_key = noise_shakehand_payload.identity_key;
    let id_sig = noise_shakehand_payload.identity_sig;

    let id_pub_key = identity::PublicKey::from_protobuf_encoding(&id_key).unwrap();
    return id_pub_key.verify(&[b"noise-libp2p-static-key:", remote_static].concat(), &id_sig);
}

pub async fn generate_handshake_payload(identity: KeypairIdentity) -> Vec<u8> {
    let mut pb = payload_proto::NoiseHandshakePayload::default();
    pb.identity_key = identity.public.clone().into_protobuf_encoding();
    info!("public key:{}", bs58::encode(pb.identity_key.as_slice()).into_string());
    pb.identity_sig = identity.signature.clone().unwrap();
    info!("signature:{}", bs58::encode(pb.identity_sig.as_slice()).into_string());
    let mut msg = Vec::with_capacity(pb.encoded_len());
    pb.encode(&mut msg).unwrap();
    return msg;
}

pub async fn write_relay(stream: &mut NegotiatedSubstream, mut relay: relay_proto::Relay) -> String {
    let mut relay_data = Vec::new();
    relay.encode(&mut relay_data);
    let key = from_bytes_get_id(&relay_data);
    relay.id = key.clone();
    let mut relay_data = Vec::new();
    relay.encode(&mut relay_data);

    upgrade::write_with_len_prefix(stream, &relay_data).map_err(|e| {
        info!("write relay error:{:?}", e);
        io::Error::new(io::ErrorKind::InvalidData, e)
    }).await.unwrap();
    info!("write relay");
    return key;
}

pub async fn write_relay_wake(stream: &mut NegotiatedSubstream) {
    let mut relay = relay_proto::Relay {
        id: String::from(""),
        r#type: relay_proto::Relaytype::Wake as i32,
        data: Vec::new(),
    };
    write_relay(stream, relay).await;
}

pub async fn write_set_session(stream: &mut NegotiatedSubstream, session_id: String) -> String {
    let cmd = relay_proto::SetSessionIdMsg {
        session_id: session_id,
        role: SessionRole::EntryRole as i32,
    };
    let mut data = Vec::new();
    cmd.encode(&mut data).unwrap();

    let mut relay = relay_proto::Relay {
        id: String::from(""),
        r#type: relay_proto::Relaytype::SetSessionId as i32,
        data: data,
    };
    return write_relay(stream, relay).await;
}

pub async fn write_payload(stream: &mut NegotiatedSubstream, buf: &[u8], len: usize, session_id: &str) {
    let mut new_buf = Vec::with_capacity(2 + len);
    new_buf.put_u16(len as u16);
    buf.iter().for_each(|x| new_buf.put_u8(*x));
    let relay_msg = relay_proto::RelayMsg {
        session_id: String::from(session_id),
        data: new_buf,
    };
    let mut relay_msg_data = Vec::new();
    relay_msg.encode(&mut relay_msg_data);
    let mut relay = relay_proto::Relay {
        id: String::from(""),
        r#type: relay_proto::Relaytype::Data as i32,
        data: relay_msg_data,
    };
    write_relay(stream, relay).await;
}

pub async fn write_encrypted_payload(stream: &mut NegotiatedSubstream, payload: &[u8], buf: &mut [u8], session_id: &str, noise: &mut TransportState) {
    //write encrypt first
    let len = noise.write_message(payload, buf).unwrap();
    let buf_tmp = &buf[..len];
    write_payload(stream, buf_tmp, len, session_id).await;
}

pub async fn write_handshake_payload(stream: &mut NegotiatedSubstream, buf: &[u8], len: usize, session_id: &str) {
    write_payload(stream, buf, len, session_id).await;
}

pub async fn read_payload(stream: &mut NegotiatedSubstream) -> Vec<u8> {
    let relay = loop {
        let relay_inner = read_from_negotiated(stream).await;
        if relay_inner.r#type == (relay_proto::Relaytype::Data as i32) {
            break relay_inner;
        }
    };

    let relay_msg = relay_proto::RelayMsg::decode(relay.data.as_slice()).unwrap();
    info!("read decrypt relay msg data len:{}", relay_msg.data.len());
    let buf_len = relay_msg.data[0] as usize * 256 + relay_msg.data[1] as usize;
    info!("relay data len:{},real buf len:{}", relay_msg.data.len(), buf_len);
    relay_msg.data[2..(2 + buf_len)].to_vec()
}

pub async fn read_and_decrypt_payload(stream: &mut NegotiatedSubstream, noise: &mut TransportState, buf: &mut [u8]) -> usize {
    let payload = read_payload(stream).await;

    return noise.read_message(&payload, buf).unwrap();
}

pub async fn read_handshake_payload(stream: &mut NegotiatedSubstream, noise: &mut HandshakeState, buf: &mut [u8]) -> usize {
    let payload = read_payload(stream).await;

    return noise.read_message(&payload, buf).unwrap();
}

pub async fn read_from_negotiated(stream: &mut NegotiatedSubstream) -> relay_proto::Relay {
    let msg = upgrade::read_one(stream, 4096)
        .map_err(|e| {
            info!("receive relay error:{:?}", e);
            io::Error::new(io::ErrorKind::InvalidData, e)
        }).await.unwrap();
    let relay = relay_proto::Relay::decode(msg.as_slice()).unwrap();
    return relay;
}

pub async fn new_circuit(remote_whitenoise_id: String, local_white_noise_id: String, local_peer_id: String, session_id: String, proxy_id: PeerId, event_bus: std::sync::Arc<std::sync::RwLock<std::collections::HashMap<String, oneshot::Sender<AckRequest>>>>, node_request_sender: mpsc::UnboundedSender<NodeRequest>) {
    let from = from_whitenoise_to_hash(local_white_noise_id);
    let to = from_whitenoise_to_hash(remote_whitenoise_id);
    let new_circuit = request_proto::NewCircuit {
        from: from,
        to: to,
        session_id: session_id,
    };
    let mut data = Vec::new();
    new_circuit.encode(&mut data).unwrap();
    let mut request = request_proto::Request {
        req_id: String::from(""),
        from: local_peer_id,
        reqtype: request_proto::Reqtype::NewCircuit as i32,
        data: data,
    };

    let key = from_request_get_id(&request);
    request.req_id = key.clone();

    let proxy_request = ProxyRequest(request.clone());

    let node_proxy_request = NodeProxyRequest {
        remote_peer_id: proxy_id.clone(),
        proxy_request: Some(proxy_request),
    };

    let AckRequest(data) = external_send_node_request_and_wait(event_bus, node_request_sender, key, NodeRequest::ProxyRequest(node_proxy_request)).await;

    println!("finished new circuit:{}", data.command_id);
}

