use async_trait::async_trait;

use libp2p::{
    noise::{NoiseConfig, X25519Spec, Keypair},
    identify,NetworkBehaviour,swarm::{NetworkBehaviourEventProcess,SwarmBuilder},
    request_response::{RequestResponseMessage,ProtocolSupport,RequestResponseEvent,RequestResponseConfig,RequestResponse,RequestResponseCodec,ProtocolName},
    Swarm,
    Multiaddr,PeerId,
    Transport,
    core::upgrade::{self,read_one,write_one,write_with_len_prefix},
    identity,
    mplex,
    tcp::TokioTcpConfig,
};

use crate::{request_proto,command_proto};
use futures::{prelude::*,channel::oneshot};
use rand::{self, Rng};
use std::{collections::VecDeque, iter};
use std::error::Error;
use tokio::io::{self, AsyncBufReadExt};
use prost::Message;
use multihash::{Code, MultihashDigest};
use tokio::sync::mpsc;
use log::{info,debug};
use libp2p::swarm::{
    NegotiatedSubstream,
    KeepAlive,
    SubstreamProtocol,
    ProtocolsHandler,
    ProtocolsHandlerEvent,
    ProtocolsHandlerUpgrErr
};
use libp2p::core::{
    InboundUpgrade,
    OutboundUpgrade,
    UpgradeInfo,
    UpgradeError,
};
use libp2p::core::upgrade::ReadOneError;

use futures::future::BoxFuture;
use futures::prelude::*;
use std::{
    fmt,
    num::NonZeroU32,
    task::{Context, Poll},
    time::Duration
};
use void::Void;
use crate::relay_proto;


pub struct RelayHandler {
    inbound: Vec<NegotiatedSubstream>,
    outbound: Vec<NegotiatedSubstream>,
    events: VecDeque<RelayHandlerEvent>
}

#[derive(Debug)]
pub enum RelayHandlerEvent {
    InboundRelay(NegotiatedSubstream),
    OutBoundRelay(NegotiatedSubstream),
    Dial(PeerId)
}

use std::{pin::Pin};

impl RelayHandler {
    pub fn new() -> Self {
        RelayHandler {
            inbound: Vec::new(),
            outbound: Vec::new(),
            events: VecDeque::new()
        }
    }
}

impl ProtocolsHandler for RelayHandler {
    type InEvent = PeerId;
    type OutEvent = RelayHandlerEvent;
    type Error = ReadOneError;
    type InboundProtocol = RelayProtocol;
    type OutboundProtocol = RelayProtocol;
    type OutboundOpenInfo = ();
    type InboundOpenInfo = ();

    fn listen_protocol(&self) -> SubstreamProtocol<RelayProtocol, ()> {
        SubstreamProtocol::new(RelayProtocol, ())
    }

    fn inject_fully_negotiated_inbound(&mut self, stream: NegotiatedSubstream, (): ()) {
        if self.inbound.len()>0 {
            panic!("already have inbound");
        }
        log::debug!("ProtocolsHandler::inject_fully_negotiated_inbound");

        self.inbound.push(stream);
    }

    fn inject_fully_negotiated_outbound(&mut self, stream: NegotiatedSubstream, (): ()) {
        if self.outbound.len()>0 {
            panic!("already have outbound");
        }
        log::debug!("ProtocolsHandler::inject_fully_negotiated_outbound");
        self.outbound.push(stream);
    }

    fn inject_event(&mut self, x: PeerId) {
        self.events.push_back(RelayHandlerEvent::Dial(x));
    }

    fn inject_dial_upgrade_error(&mut self, _info: (), error: ProtocolsHandlerUpgrErr<Void>) {
        log::debug!("ProtocolsHandler::inject_dial_upgrade_error: {:?}", error);
    }

    fn connection_keep_alive(&self) -> KeepAlive {
        KeepAlive::Yes
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<
        ProtocolsHandlerEvent<
            RelayProtocol,
            (),
            RelayHandlerEvent,
            Self::Error
        >
    > {
        log::debug!("ProtocolsHandler::poll begins...");
        if  self.inbound.len()>0{
            let stream_s = self.inbound.remove(0);
            return Poll::Ready(ProtocolsHandlerEvent::Custom( RelayHandlerEvent::InboundRelay(stream_s)));
        }
        if self.outbound.len()>0{
            let stream_s = self.outbound.remove(0);
            return Poll::Ready(ProtocolsHandlerEvent::Custom( RelayHandlerEvent::OutBoundRelay(stream_s)));
        }
        if self.events.pop_front().is_some(){
            return Poll::Ready(ProtocolsHandlerEvent::OutboundSubstreamRequest{
                protocol: SubstreamProtocol::new(RelayProtocol, ())
            })
        }
        
        Poll::Pending
    }

}


#[derive(Default, Debug, Copy, Clone)]
pub struct RelayProtocol;

impl InboundUpgrade<NegotiatedSubstream> for RelayProtocol {
    type Output = NegotiatedSubstream;
    type Error = Void;
    //type Future = Future<<Result<Self::Output, Self::Error>>>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_inbound(self, mut stream: NegotiatedSubstream, _: Self::Info) -> Self::Future {
        log::debug!("InboundUpgrade::upgrade_inbound");
        let z = async{
            {
                let msg = upgrade::read_one(&mut stream, 4096)
                .map_err(|e| {
                    info!("receive relay error:{:?}",e);
                    io::Error::new(io::ErrorKind::InvalidData, e)
                }).await.unwrap();
                let relay_wake = relay_proto::Relay::decode(msg.as_slice()).unwrap();
                info!("received relay:{:?}",relay_wake);
            }
            Ok(stream)
        };
        z.boxed()
    }
}

impl OutboundUpgrade<NegotiatedSubstream> for RelayProtocol {
    type Output = NegotiatedSubstream;
    type Error = Void;
    type Future = future::Ready<Result<Self::Output, Self::Error>>;

    fn upgrade_outbound(self, stream: NegotiatedSubstream, _: Self::Info) -> Self::Future {
        log::debug!("OutboundUpgrade::upgrade_outbound");
        future::ok(stream)
    }
}

impl UpgradeInfo for RelayProtocol {
    type Info = &'static [u8];
    type InfoIter = iter::Once<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        iter::once(b"/relay")
    }
}

