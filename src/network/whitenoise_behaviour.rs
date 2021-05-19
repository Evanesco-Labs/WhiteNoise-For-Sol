use async_trait::async_trait;

use libp2p::{
    Multiaddr,
    NetworkBehaviour,
    PeerId, Swarm,
    Transport, core::upgrade::{self, read_one, write_one, write_with_len_prefix},
    identify, identity, mplex, noise::{NoiseConfig, X25519Spec, Keypair},
    request_response::{RequestResponseMessage, ProtocolSupport, RequestResponseEvent,
                       RequestResponseConfig, RequestResponse, RequestResponseCodec, ProtocolName},
    swarm::{NegotiatedSubstream, NetworkBehaviour, NetworkBehaviourEventProcess, SwarmBuilder},
    tcp::TokioTcpConfig,
};

use crate::{request_proto, command_proto};
use futures::{prelude::*, channel::oneshot};
use rand::{self, Rng};
use std::{collections::VecDeque, iter};
use std::error::Error;
use tokio::io::{self, AsyncBufReadExt};
use prost::Message;
use multihash::{Code, MultihashDigest};
use tokio::sync::mpsc;
use log::{info, debug, warn};
use super::protocols::proxy_protocol::{ProxyCodec, ProxyRequest, ProxyResponse};
use super::protocols::ack_protocol::{AckCodec, AckRequest, AckResponse};
use super::protocols::relay_behaviour::{RelayEvent, Relay};
use smallvec::SmallVec;

pub struct NodeAckRequest {
    pub remote_peer_id: PeerId,
    pub ack_request: std::option::Option<AckRequest>,
}

pub struct NodeNewStream {
    pub peer_id: PeerId,
}

pub struct NodeProxyRequest {
    pub remote_peer_id: PeerId,
    pub proxy_request: std::option::Option<ProxyRequest>,
}

pub struct AddPeerAddresses {
    pub remote_peer_id: PeerId,
    pub remote_addr: SmallVec<[Multiaddr; 6]>,
}

pub enum NodeRequest {
    ProxyRequest(NodeProxyRequest),
    AckRequest(NodeAckRequest),
    NewStreamRequest(NodeNewStream),
    AddPeerAddressesRequest(AddPeerAddresses),
}


#[derive(NetworkBehaviour)]
pub struct WhitenoiseBehaviour {
    pub proxy_behaviour: RequestResponse<ProxyCodec>,
    pub ack_behaviour: RequestResponse<AckCodec>,
    pub identify_behaviour: identify::Identify,
    pub relay_behaviour: Relay,
    #[behaviour(ignore)]
    pub event_bus: std::sync::Arc<std::sync::RwLock<std::collections::HashMap<String, oneshot::Sender<AckRequest>>>>,
    #[behaviour(ignore)]
    pub relay_streams: std::sync::Arc<std::sync::RwLock<VecDeque<NegotiatedSubstream>>>,
    #[behaviour(ignore)]
    pub proxy_request_channel: mpsc::UnboundedSender<NodeProxyRequest>,
}

impl NetworkBehaviourEventProcess<RelayEvent> for WhitenoiseBehaviour {
    fn inject_event(&mut self, message: RelayEvent) {
        match message {
            RelayEvent::Relay(x) => {
                let mut guard = self.relay_streams.write().unwrap();
                (*guard).push_back(x);
            }
            _ => {
                warn!("unknown relay event poll");
            }
        }
    }
}


impl NetworkBehaviourEventProcess<RequestResponseEvent<ProxyRequest, ProxyResponse>> for WhitenoiseBehaviour {
    fn inject_event(&mut self, message: RequestResponseEvent<ProxyRequest, ProxyResponse>) {
        match message {
            RequestResponseEvent::InboundFailure { peer, request_id, error } => {
                debug!("proxy inbound failure:{:?}", error);
            }
            RequestResponseEvent::OutboundFailure { peer, request_id: req_id, error } => {
                debug!("proxy outbound failure:{:?}", error);
            }
            RequestResponseEvent::Message { peer, message } => {
                debug!("proxy received mssage:{:?}", message);
                match message {
                    RequestResponseMessage::Request { request_id, request, .. } => {
                        let node_proxy_request = NodeProxyRequest {
                            remote_peer_id: peer,
                            proxy_request: Some(request),
                        };
                        self.proxy_request_channel.send(node_proxy_request);
                    }
                    _ => {}
                }
            }
            RequestResponseEvent::ResponseSent { peer, request_id } => {
                debug!("proxy send response:{:?}", request_id);
            }
        }
    }
}

impl NetworkBehaviourEventProcess<RequestResponseEvent<AckRequest, AckResponse>> for WhitenoiseBehaviour {
    fn inject_event(&mut self, message: RequestResponseEvent<AckRequest, AckResponse>) {
        match message {
            RequestResponseEvent::InboundFailure { peer, request_id, error } => {
                debug!("ack inbound failure:{:?}", error);
            }
            RequestResponseEvent::OutboundFailure { peer, request_id: req_id, error } => {
                debug!("ack outbound failure:{:?}", error);
            }
            RequestResponseEvent::Message { peer, message } => {
                debug!("ack received mssage:{:?}", message);
                match message {
                    RequestResponseMessage::Request { request_id, request, channel } => {
                        let AckRequest(data) = request.clone();
                        let mut guard = self.event_bus.write().unwrap();
                        debug!("receive {}", data.command_id);
                        let mut sender_option = (*guard).remove(&(data.command_id));
                        match sender_option {
                            Some(mut sender) => {
                                debug!("ack prepare to send");
                                sender.send(request.clone());
                            }
                            None => {
                                debug!("ack prepare to send,but no sender");
                            }
                        }
                    }
                    _ => {}
                }
            }
            RequestResponseEvent::ResponseSent { peer, request_id } => {
                debug!("ack send response:{:?}", request_id);
            }
        }
    }
}

impl NetworkBehaviourEventProcess<identify::IdentifyEvent> for WhitenoiseBehaviour {
    // Called when `floodsub` produces an event.
    fn inject_event(&mut self, message: identify::IdentifyEvent) {
        match message {
            identify::IdentifyEvent::Received { peer_id, info, observed_addr } => {}
            identify::IdentifyEvent::Sent { peer_id } => {}
            identify::IdentifyEvent::Error { peer_id, error } => {}
        }
    }
}

pub async fn whitenoise_event_loop(mut swarm1: Swarm<WhitenoiseBehaviour>, mut node_request_receiver: tokio::sync::mpsc::UnboundedReceiver<NodeRequest>) {
    loop {
        tokio::select! {
            event = swarm1.next() => {
                panic!("Unexpected event: {:?}", event);
            }
            Some(node_request) = node_request_receiver.recv() =>{

                match node_request{
                    NodeRequest::ProxyRequest(node_proxy_request)=>{
                        swarm1.proxy_behaviour.send_request(&(node_proxy_request.remote_peer_id),node_proxy_request.proxy_request.unwrap().clone());
                    }
                    NodeRequest::AddPeerAddressesRequest(add_peer_addresses) =>{
                        add_peer_addresses.remote_addr.iter().for_each(|x|{
                            swarm1.ack_behaviour.add_address(&(add_peer_addresses.remote_peer_id),x.clone());
                            swarm1.proxy_behaviour.add_address(&(add_peer_addresses.remote_peer_id),x.clone());
                        });
                        swarm1.relay_behaviour.addresses.insert(add_peer_addresses.remote_peer_id, add_peer_addresses.remote_addr);
                    }
                    NodeRequest::AckRequest(node_ack_request)=>{
                        swarm1.ack_behaviour.send_request(&(node_ack_request.remote_peer_id),node_ack_request.ack_request.unwrap().clone());

                    }
                    NodeRequest::NewStreamRequest(node_new_stream)=>{
                        let peer_addr = swarm1.relay_behaviour.addresses.get(&node_new_stream.peer_id).unwrap().clone();
                        swarm1.relay_behaviour.new_stream(&node_new_stream.peer_id);
                    }
                }
            }

        }
    }
}


