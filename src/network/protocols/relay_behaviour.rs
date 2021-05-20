use libp2p::{
    Multiaddr,
    PeerId,
    core::connection::{ConnectionId, ConnectedPoint},
    swarm::{
        DialPeerCondition,
        NetworkBehaviour,
        NetworkBehaviourAction,
        NotifyHandler,
        PollParameters,
        NegotiatedSubstream,
    },
};
use log::{info, debug};

use std::{collections::{HashMap, HashSet, VecDeque}, fmt, ops::Mul, sync::{atomic::AtomicU64, Arc}, task::{Context, Poll}, time::Duration};
use super::relay_protocol::{RelayHandler, RelayHandlerEvent};
use smallvec::SmallVec;

pub struct Relay {
    pub events: VecDeque<RelayHandlerEvent>,
    pub addresses: std::collections::HashMap<PeerId, SmallVec<[Multiaddr; 6]>>,
}

impl Relay {
    pub fn new_stream(&mut self, peer_id: &PeerId) {
        self.events.push_back(RelayHandlerEvent::Dial(peer_id.clone()))
    }
}

pub enum RelayEvent {
    InboundRelay(NegotiatedSubstream),
    OutboundRelay(NegotiatedSubstream),
}

impl NetworkBehaviour for Relay {
    type ProtocolsHandler = RelayHandler;
    type OutEvent = RelayEvent;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        RelayHandler::new()
    }

    fn addresses_of_peer(&mut self, _peer_id: &PeerId) -> Vec<Multiaddr> {
        let mut addresses = Vec::new();
        let exist_addresses_option = self.addresses.get(_peer_id);
        if exist_addresses_option.is_some() {
            let exist_addresses = exist_addresses_option.unwrap();
            exist_addresses.iter().for_each(|x| addresses.push(x.clone()))
        }
        addresses
    }

    fn inject_connected(&mut self, _: &PeerId) {
        debug!("relay connected");
    }
    fn inject_connection_established(&mut self, _: &PeerId, _: &ConnectionId, _: &ConnectedPoint)
    {
        debug!("relay connection established");
    }

    fn inject_disconnected(&mut self, _: &PeerId) {}

    fn inject_event(&mut self, peer: PeerId, _: ConnectionId, result: RelayHandlerEvent) {
        self.events.push_front(result);
    }

    fn poll(&mut self, _: &mut Context<'_>, _: &mut impl PollParameters)
            -> Poll<NetworkBehaviourAction<PeerId, RelayEvent>>
    {
        if let Some(e) = self.events.pop_back() {
            match e {
                RelayHandlerEvent::InboundRelay(x) => {
                    let out = RelayEvent::InboundRelay(x);
                    Poll::Ready(NetworkBehaviourAction::GenerateEvent(out))
                }
                RelayHandlerEvent::OutBoundRelay(x) => {
                    let out = RelayEvent::OutboundRelay(x);
                    Poll::Ready(NetworkBehaviourAction::GenerateEvent(out))
                }
                RelayHandlerEvent::Dial(y) => {
                    debug!("prepare to dial peer of relay");
                    // Poll::Ready(NetworkBehaviourAction::DialPeer{
                    //     peer_id: y,
                    //     condition: DialPeerCondition::Always
                    // })
                    Poll::Ready(NetworkBehaviourAction::NotifyHandler {
                        peer_id: y.clone(),
                        handler: NotifyHandler::Any,
                        event: y,
                    })
                }
                _ => {
                    Poll::Pending
                }
            }
        } else {
            Poll::Pending
        }
    }
}