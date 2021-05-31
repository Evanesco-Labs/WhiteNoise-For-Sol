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

use whitenoise_solana::network::whitenoise_behaviour::{NodeAckRequest, NodeRequest};
use whitenoise_solana::{command_proto, payload_proto, relay_proto, request_proto, chat_proto};
use futures::{prelude::*, channel::oneshot};
use rand::{self, Rng};
use std::{iter};
use std::error::Error;
use tokio::io::{self, AsyncBufReadExt};
use prost::Message;
use multihash::{Code, MultihashDigest};
use tokio::sync::mpsc;
use log::info;
use whitenoise_solana::network::{node, protocols::ack_protocol::AckRequest};
use snow::{params::NoiseParams, Builder, HandshakeState, TransportState};
use whitenoise_solana::sdk::chat_message::ChatMessage;
use clap::{Arg, App, SubCommand};
use whitenoise_solana::sdk::client;
use whitenoise_solana::sdk::client::SolanaClient;
use tokio::time::Duration;
use futures::future::ok;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let env = env_logger::Env::new().filter_or("MY_LOG", "debug");
    env_logger::init_from_env(env);

    let bootstrap_str = "/ip4/127.0.0.1/tcp/6661/p2p/16Uiu2HAm3YnU5srfPXyfTWMMqxbx61D47AaDfABYknTLGxzHy8tA";

    let mut client = client::WhiteNoiseClient::init(bootstrap_str).await;
    let local_whitenoise_id = client.get_whitenoise_id();
    info!("local whitenoise id:{}", local_whitenoise_id);
    let peers = client.get_main_net_peers(10).await;
    info!("main net peers: {:?}", peers);

    let mut rng = rand::thread_rng();
    let index = rng.gen_range(0..peers.len());
    let proxy_peer_id = peers.get(index).unwrap();

    client.register(proxy_peer_id.clone()).await?;

    let mut session_id = String::new();
    loop {
        let mut guard = client.circuit_events.write().unwrap();
        if let Some(event) = (*guard).pop_front() {
            session_id = event;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }


    let mut stdin = io::BufReader::new(io::stdin()).lines();
    loop {
        tokio::select! {
             Ok(Some(line)) = stdin.next_line() => {
            println!("send message: {:?}", line.as_bytes());
            client.send_message(session_id.as_str(), line.as_bytes()).await;
        }
        Some(data) = client.read_message(session_id.as_str()) => {
              println!("receive message: {:?}",data);
        }
        }
    }

    Ok(())
}







