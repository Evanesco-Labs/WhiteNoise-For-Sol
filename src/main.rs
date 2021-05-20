use async_trait::async_trait;

use bytes::BufMut;
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
    noise,
    noise::KeypairIdentity,
};

pub mod request_proto {
    include!(concat!(env!("OUT_DIR"), "/request_proto.rs"));
}

pub mod command_proto {
    include!(concat!(env!("OUT_DIR"), "/command_proto.rs"));
}

pub mod gossip_proto {
    include!(concat!(env!("OUT_DIR"), "/gossip_proto.rs"));
}

pub mod relay_proto {
    include!(concat!(env!("OUT_DIR"), "/relay_proto.rs"));
}

pub mod payload_proto {
    include!(concat!(env!("OUT_DIR"), "/payload.proto.rs"));
}

pub mod chat_proto {
    include!(concat!(env!("OUT_DIR"), "/chat_proto.rs"));
}

pub mod network;
pub mod sdk;
pub mod account;

use network::whitenoise_behaviour::{NodeAckRequest, NodeRequest};

use futures::{prelude::*, channel::oneshot};
use rand::{self, Rng};
use std::{iter};
use std::error::Error;
use tokio::io::{self, AsyncBufReadExt};
use prost::Message;
use multihash::{Code, MultihashDigest};
use tokio::sync::mpsc;
use log::info;
use network::{node, protocols::ack_protocol::AckRequest};
use snow::{params::NoiseParams, Builder, HandshakeState, TransportState};
use sdk::chat_message::ChatMessage;
use clap::{Arg, App, SubCommand};
use crate::sdk::client::generate_session_id;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let env = env_logger::Env::new().filter_or("MY_LOG", "debug");
    env_logger::init_from_env(env);

    let args = App::new("whitenoise")
        .version("1.0")
        .about("whitenoise")
        .arg(Arg::with_name("bootstrap")
            .short("b")
            .long("bootstrap")
            .help("PeerId of the node to bootstrap from.")
            .required(true)
            .takes_value(true))
        .arg(Arg::with_name("id")
            .short("i")
            .long("id")
            .help("WhiteNoiseID of the node to connect to.")
            .takes_value(true))
        .arg(Arg::with_name("name")
            .short("n")
            .long("name")
            .help("Customize name of the client")
            .required(true)
            .takes_value(true))
        .get_matches();

    let bootstrap_addr_str = args.value_of("bootstrap").unwrap();
    info!("bootstrap_addr:{}", bootstrap_addr_str);
    let nick_name = String::from(args.value_of("name").unwrap());
    info!("nick:{}", nick_name);
    let remote_whitenoise_id_option = args.value_of("id");

    let parts: Vec<&str> = bootstrap_addr_str.split('/').collect();
    let bootstrap_peer_id_str = parts.get(parts.len() - 1).unwrap();
    info!("bootstrap peer id:{}", bootstrap_peer_id_str);
    let bootstrap_peer_id = PeerId::from_bytes(bs58::decode(bootstrap_peer_id_str).into_vec().unwrap().as_slice()).unwrap();
    let bootstrap_addr: Multiaddr = bootstrap_addr_str.parse()?;

    let mut node = node::start().await;
    log::info!("get node");
    let peer_list = node.get_main_nets(10, bootstrap_peer_id, bootstrap_addr).await;
    log::info!("get main_net");
    let mut index = rand::random::<usize>();
    index = index % peer_list.peers.len();
    let node_info = peer_list.peers.get(index).unwrap();
    info!("id:{},addr_len:{},addr:{:?}", node_info.id, node_info.addr.len(), node_info.addr);

    let proxy_remote_id = PeerId::from_bytes(bs58::decode(node_info.id.as_str()).into_vec().unwrap().as_slice()).unwrap();

    node.register_proxy(proxy_remote_id).await;
    //dial
    if remote_whitenoise_id_option.is_some() {
        caller(String::from(remote_whitenoise_id_option.unwrap()), node, proxy_remote_id, nick_name).await;
    } else {
        answer(node, nick_name).await;
    }
    Ok(())
}

pub async fn answer(mut node: node::Node, nick_name: String) {
    let mut stream = node.wait_for_inbound_relay_stream().await;
    info!("received relay steam");
    let relay = loop {
        let relay_inner = node::read_from_negotiated(&mut stream).await;
        ;
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


    let mut stdin = io::BufReader::new(io::stdin()).lines();
    let mut buf = [0u8; 65536];
    loop {
        tokio::select! {
            Ok(Some(line)) = stdin.next_line() =>{
                let chat_message = ChatMessage{peerID:nick_name.clone(),data: line.as_bytes().to_vec()};
                let chat_message_str = serde_json::to_string(&chat_message).unwrap();
                let mut payload = Vec::new();
                payload.put_u32(chat_message_str.len() as u32);
                chat_message_str.as_bytes().iter().for_each(|x| payload.put_u8(*x));
                node::write_encrypted_payload(&mut stream, &payload, &mut buf, session_id.as_str(),&mut noise).await;
            }
            len = node::read_and_decrypt_payload(&mut stream,&mut noise,&mut buf) =>{
                let real_size = u32::from_be_bytes([buf[0],buf[1],buf[2],buf[3]]) as usize;
                info!("real size:{},buf len:{}",real_size,len);
                let b2 = &buf[4..(real_size+4)];
 
                println!("receive chatmessage:{}",String::from_utf8_lossy(b2));
            }
        }
    }
}

pub async fn caller(remote_whitenoise_id: String, mut node: node::Node, proxy_remote_id: PeerId, nick_name: String) {
    let public_key_secp256k1 = match node.keypair.public() {
        identity::PublicKey::Secp256k1(k) => k,
        _ => {
            panic!("hahha");
        }
    };
    let local_whitenoise_id = bs58::encode(public_key_secp256k1.encode()).into_string();

    let session_id = generate_session_id(remote_whitenoise_id.clone(), local_whitenoise_id.clone());
    info!("session_id:{}", session_id);
    {
        let mut guard = node.circuit_task.write().unwrap();
        (*guard).insert(session_id.clone(), bs58::decode(remote_whitenoise_id.clone()).into_vec().unwrap());
    }
    //new relay stream
    let remote_pub_key_bytes = bs58::decode(remote_whitenoise_id.as_str()).into_vec().unwrap();
    let remote_pub_key = identity::secp256k1::PublicKey::decode(&remote_pub_key_bytes).unwrap();
    let remote_peer_id = PeerId::from_public_key(identity::PublicKey::Secp256k1(remote_pub_key));

    node.new_relay_stream(proxy_remote_id).await;
    let mut stream = node.wait_for_outbound_relay_stream().await;
    info!("received relay steam");

    node::write_relay_wake(&mut stream).await;
    //set session id
    let key = node::write_set_session(&mut stream, session_id.clone()).await;
    let (r, s) = oneshot::channel();
    {
        let mut guard = node.event_bus.write().unwrap();
        (*guard).insert(key, r);
    }
    let ack_request = s.await.unwrap();
    let AckRequest(ack) = ack_request;
    info!("receive set session ack:{:?}", ack);


    node::new_circuit(remote_whitenoise_id, local_whitenoise_id, PeerId::from(node.keypair.public()).to_base58(), session_id.clone(), node.proxy_id.clone().unwrap(), node.event_bus.clone(), node.node_request_sender.clone()).await;

    loop {
        let relay = node::read_from_negotiated(&mut stream).await;

        if relay.r#type == (relay_proto::Relaytype::Success as i32) {
            info!("received relay success:{:?}", relay);
            break;
        }
    }

    let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
        .into_authentic(&node.keypair)
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

    let mut stdin = io::BufReader::new(io::stdin()).lines();
    let mut buf = [0u8; 65536];
    loop {
        tokio::select! {
            Ok(Some(line)) = stdin.next_line() =>{
                let chat_message = ChatMessage{peerID:nick_name.clone(),data: line.as_bytes().to_vec()};
                let chat_message_str = serde_json::to_string(&chat_message).unwrap();
                let mut payload = Vec::new();
                payload.put_u32(chat_message_str.len() as u32);
                chat_message_str.as_bytes().iter().for_each(|x| payload.put_u8(*x));
                node::write_encrypted_payload(&mut stream, &payload, &mut buf, session_id.as_str(),&mut noise).await;
            }
            len = node::read_and_decrypt_payload(&mut stream,&mut noise,&mut buf) =>{
                let real_size = u32::from_be_bytes([buf[0],buf[1],buf[2],buf[3]]) as usize;
                info!("real size:{},buf len:{}",real_size,len);
                let b2 = &buf[4..(real_size+4)];
 
                println!("receive chatmessage:{}",String::from_utf8_lossy(b2));
            }
        }
    }
}



