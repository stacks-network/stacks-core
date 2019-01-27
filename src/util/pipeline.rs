/*
 copyright: (c) 2013-2018 by Blockstack PBC, a public benefit corporation.

 This file is part of Blockstack.

 Blockstack is free software. You may redistribute or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License or
 (at your option) any later version.

 Blockstack is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY, including without the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
*/


use std::sync::Arc;
use std::sync::mpsc::{SyncSender, Receiver};
use std::sync::mpsc::sync_channel;

use util::Error as util_error;

pub trait PipelineProcessor<I, O, C> 
where
    I: Sync + Send,
    O: Sync + Send
{
    fn process(&mut self, item: &I, context: &mut C) -> Result<O, String>;
}

pub struct PipelineStage<I, O>
where
    I: Sync + Send,
    O: Sync + Send
{
    chan_in: Option<Receiver<Arc<I>>>,
    chan_out: Option<SyncSender<Arc<O>>>,

    source: Option<Vec<I>>,
    sink: bool
}

impl<I, O> PipelineStage<I, O> 
where
    I: Sync + Send,
    O: Sync + Send
{
    pub fn new() -> PipelineStage<I, O> {
        PipelineStage {
            chan_in: None,
            chan_out: None,
            source: None,
            sink: false
        }
    }

    pub fn new_source(inputs: Vec<I>) -> PipelineStage<I, O> {
        PipelineStage {
            chan_in: None,
            chan_out: None,
            source: Some(inputs.into_iter().rev().collect()),
            sink: false
        }
    }

    pub fn new_sink() -> PipelineStage<I, O> {
        PipelineStage {
            chan_in: None,
            chan_out: None,
            source: None,
            sink: true
        }
    }

    fn recv(&mut self) -> Result<Arc<I>, util_error> {
        match self.source {
            None => {
                match self.chan_in {
                    Some(ref mut channel) => {
                        channel.recv()
                            .map_err(|e| util_error::RecvError(e))
                    },
                    None => {
                        Err(util_error::ChannelNotConnected)
                    }
                }
            },
            Some(ref mut inputs) => {
                let next_opt = inputs.pop();
                match next_opt {
                    Some(input) => {
                        Ok(Arc::new(input))
                    },
                    None => {
                        Err(util_error::ChannelSourceDrained)
                    }
                }
            }
        }
    }

    fn send(&mut self, output: O) -> Result<(), util_error> {
        if !self.sink {
            match self.chan_out {
                Some(ref mut channel) => {
                    channel.send(Arc::new(output))
                        .map_err(|e| util_error::SendError)
                },
                None => Err(util_error::ChannelNotConnected)
            }
        }
        else {
            // no-op
            Ok(())
        }
    }

    pub fn next<P, C>(&mut self, mut p: P, ctx: &mut C) -> Result<(), util_error>
    where
        P: PipelineProcessor<I, O, C>
    {
        let arc_i = self.recv()?;
        let out = p.process(&arc_i, ctx)
            .map_err(|se| util_error::ProcessError(se))?;

        self.send(out)?;
        Ok(())
    }

    pub fn connect<A, T, B>(stage1: &mut PipelineStage<A, T>, stage2: &mut PipelineStage<T, B>, bufsize: usize)
    where
        A: Send + Sync,
        T: Send + Sync,
        B: Send + Sync
    {
        let (sender, receiver) = sync_channel::<Arc<T>>(bufsize);
        stage1.chan_out = Some(sender);
        stage2.chan_in = Some(receiver);
    }
}
