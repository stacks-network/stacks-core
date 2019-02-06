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
use std::thread;

use std::sync::mpsc::RecvError as recv_error;

use util::Error as util_error;

pub trait PipelineProcessor<I, O> 
where
    I: Sync + Send,
    O: Sync + Send
{
    fn process(&mut self, item: &I) -> Result<O, String>;
}

pub struct PipelineStage<I, O>
where
    I: Sync + Send,
    O: Sync + Send
{
    chan_in: Option<Receiver<Arc<I>>>,
    chan_out: Option<SyncSender<Arc<O>>>,

    source: Option<Vec<I>>,
    term: bool,
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
            term: false
        }
    }

    pub fn new_source(inputs: Vec<I>) -> PipelineStage<I, O> {
        PipelineStage {
            chan_in: None,
            chan_out: None,
            source: Some(inputs.into_iter().rev().collect()),
            term: false
        }
    }

    pub fn new_terminus(input_channel: Receiver<Arc<I>>) -> PipelineStage<I, O> {
        PipelineStage {
            chan_in: Some(input_channel),
            chan_out: None,
            source: None,
            term: true
        }
    }

    pub fn new_sink(out_channel: SyncSender<Arc<O>>) -> PipelineStage<I, O> {
        PipelineStage {
            chan_in: None,
            chan_out: Some(out_channel),
            source: None,
            term: false
        }
    }

    fn recv(&mut self) -> Result<Arc<I>, util_error> {
        match self.source {
            None => {
                match self.chan_in {
                    Some(ref mut channel) => {
                        channel.recv()
                            .map_err(|e| util_error::ChannelNotConnected)
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
        if !self.term {
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

    // returns true if this method can be called again
    // returns false if the sender was disconnected
    // returns Err otherwise -- i.e. if the processor fails
    pub fn next<P>(&mut self, processor: &mut P) -> Result<bool, util_error>
    where
        P: PipelineProcessor<I, O>
    {
        match self.recv() {
            Ok(arc_i) => {
                let out = processor.process(&arc_i)
                    .map_err(|se| util_error::ProcessError(se))?;

                match self.send(out) {
                    Ok(()) => Ok(true),
                    Err(util_error::ChannelNotConnected) => Ok(false),
                    Err(_e) => Err(_e)
                }
            },
            Err(util_error::ChannelNotConnected) | Err(util_error::ChannelSourceDrained) => Ok(false),
            Err(_e) => Err(_e)
        }
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

    /*
    pub fn thread<'a, P>(stage: &'a mut PipelineStage<I, O>, processor: &'a mut P) -> thread::JoinHandle<Result<(), util_error>>
    where
        P: PipelineProcessor<I, O> + Send,
    {
        thread::spawn(|| {
            while true {
                match stage.next(processor) {
                    Ok(true) => {
                        continue;
                    }
                    Ok(false) => {
                        break;
                    }
                    Err(e) => {
                        return Err(e);
                    }
                }
            }
            Ok(())
        })
    }
    */
}
