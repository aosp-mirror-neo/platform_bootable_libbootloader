// Copyright 2024, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! This file provides async utility APIs used by GBL.
//!
//! They are mainly barebone APIs for busy waiting and polling Futures. There is no support for
//! sleep/wake or threading.

#![cfg_attr(not(test), no_std)]

use core::{
    future::Future,
    ops::DerefMut,
    pin::{pin, Pin},
    task::{Context, Poll, Waker},
};
use trace::{gbl_trace_get_enable, TraceGuard};

/// Repetitively polls and blocks until a future completes.
pub fn block_on<O>(fut: impl Future<Output = O>) -> O {
    block_on_mut(&mut pin!(fut))
}

/// Repetitively polls and blocks until a pinned future completes.
pub fn block_on_mut<O, F: Future<Output = O> + ?Sized>(
    fut: &mut Pin<impl DerefMut<Target = F>>,
) -> O {
    loop {
        if let Some(res) = poll(fut) {
            return res;
        }
    }
}

/// Polls a Future.
///
/// Returns Some(_) if ready, None otherwise.
pub fn poll<O, F: Future<Output = O> + ?Sized>(
    fut: &mut Pin<impl DerefMut<Target = F>>,
) -> Option<O> {
    match fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Pending => None,
        Poll::Ready(res) => Some(res),
    }
}

/// Polls the given future for up to `n` times.
pub fn poll_n_times<O, F: Future<Output = O> + ?Sized>(
    fut: &mut Pin<impl DerefMut<Target = F>>,
    n: usize,
) -> Option<O> {
    (0..n).find_map(|_| poll(fut))
}

/// `Yield` implements a simple API for yielding control once to the executor.
struct Yield(bool);

impl Future for Yield {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        self.0 = !self.0;
        match self.0 {
            true => Poll::Pending,
            _ => Poll::Ready(()),
        }
    }
}

/// Yield the execution once.
pub async fn yield_now() {
    Yield(false).await
}

/// `YieldCounter` maintains a counter and yields control to executor once it overflows a given
/// threshold. When overflow occurs, the counter value is reset and the carry over is discarded.
pub struct YieldCounter {
    threshold: u64,
    current: u64,
}

impl YieldCounter {
    /// Creates an instance with a given threshold.
    pub fn new(threshold: u64) -> Self {
        Self { threshold, current: 0 }
    }

    /// Increments the current counter and yield execution if the value overflows the threshold.
    pub async fn increment(&mut self, inc: u64) {
        self.current = self.current.saturating_sub(inc);
        if self.current == 0 {
            self.current = self.threshold;
            yield_now().await;
        }
    }
}

/// Polls a future with local trace config
///
/// The API set trace config as `fut_local_config`, polls future, saves the updated
/// config in `fut_local_config` and restores original trace config.
#[inline(always)]
pub fn poll_with_local_trace_config<O, F: Future<Output = O> + ?Sized>(
    fut: &mut Pin<impl DerefMut<Target = F>>,
    fut_local_config: &mut bool,
) -> Option<O> {
    let _guard = TraceGuard::new(*fut_local_config);
    let res = poll(fut);
    *fut_local_config = gbl_trace_get_enable();
    res
}

/// Repetitively polls two pinned futures until both of them finish.
pub async fn join_mut<L, LO, R, RO>(
    fut_lhs: &mut Pin<impl DerefMut<Target = L>>,
    fut_rhs: &mut Pin<impl DerefMut<Target = R>>,
) -> (LO, RO)
where
    L: Future<Output = LO>,
    R: Future<Output = RO>,
{
    let trace_config_orig = gbl_trace_get_enable();
    // join_mut itself may become a future in another join/select. Thus don't enable tracing to
    // prevent producing lots of polling call traces of itself.
    let _guard = TraceGuard::new(false);
    // Polling a future is similar to context switching to a thread. Makes a copy of its trace
    // config and makes sure to save and restore it for each context switch.
    let mut lhs_local_config = trace_config_orig;
    let mut rhs_local_config = trace_config_orig;
    let mut out_lhs = poll_with_local_trace_config(fut_lhs, &mut lhs_local_config);
    let mut out_rhs = poll_with_local_trace_config(fut_rhs, &mut rhs_local_config);
    while out_lhs.is_none() || out_rhs.is_none() {
        yield_now().await;
        if out_lhs.is_none() {
            out_lhs = poll_with_local_trace_config(fut_lhs, &mut lhs_local_config);
        }

        if out_rhs.is_none() {
            out_rhs = poll_with_local_trace_config(fut_rhs, &mut rhs_local_config);
        }
    }
    (out_lhs.unwrap(), out_rhs.unwrap())
}

/// Repetitively polls two futures until both of them finish.
pub async fn join<L, LO, R, RO>(fut_lhs: L, fut_rhs: R) -> (LO, RO)
where
    L: Future<Output = LO>,
    R: Future<Output = RO>,
{
    join_mut(&mut pin!(fut_lhs), &mut pin!(fut_rhs)).await
}

/// Waits until either of the given two futures completes.
pub async fn select<L, LO, R, RO>(fut_lhs: L, fut_rhs: R) -> (Option<LO>, Option<RO>)
where
    L: Future<Output = LO>,
    R: Future<Output = RO>,
{
    let trace_config_orig = gbl_trace_get_enable();
    // select itself may become a future in another join/select. Thus don't enable tracing to
    // prevent producing lots of polling call traces of itself.
    let _guard = TraceGuard::new(false);
    let fut_lhs = &mut pin!(fut_lhs);
    let fut_rhs = &mut pin!(fut_rhs);
    // Polling a future is similar to context switching to a thread. Makes a copy of its trace
    // config and makes sure to save and restore it for each context switch.
    let mut lhs_local_config = trace_config_orig;
    let mut rhs_local_config = trace_config_orig;
    let mut out_lhs = poll_with_local_trace_config(fut_lhs, &mut lhs_local_config);
    let mut out_rhs = poll_with_local_trace_config(fut_rhs, &mut rhs_local_config);
    while out_lhs.is_none() && out_rhs.is_none() {
        yield_now().await;
        out_lhs = poll_with_local_trace_config(fut_lhs, &mut lhs_local_config);
        out_rhs = poll_with_local_trace_config(fut_rhs, &mut rhs_local_config);
    }
    (out_lhs, out_rhs)
}

/// Runs a [Future] and checks and asserts that it returns eventually.
pub async fn assert_return<O>(fut: impl Future<Output = O>) -> O {
    struct Returned(bool);

    impl Drop for Returned {
        fn drop(&mut self) {
            assert!(self.0, "Future was dropped before it returned")
        }
    }

    let mut flag = Returned(false);
    let res = fut.await;
    flag.0 = true;
    res
}

#[cfg(test)]
mod test {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn test() {
        let mut counter = YieldCounter::new(1);
        let mut fut = pin!(async move {
            counter.increment(2).await;
            counter.increment(2).await;
        });

        assert!(poll(&mut fut).is_none());
        assert!(poll(&mut fut).is_none());
        assert!(poll(&mut fut).is_some());
    }

    #[test]
    fn test_join() {
        let val1 = Mutex::new(0);
        let val2 = Mutex::new(1);

        let mut join_fut = pin!(join(
            async {
                *val1.try_lock().unwrap() += 1;
                yield_now().await;
                *val1.try_lock().unwrap() += 1;
                yield_now().await;
            },
            async {
                *val2.try_lock().unwrap() += 1;
                yield_now().await;
                *val2.try_lock().unwrap() += 1;
                yield_now().await;
                *val2.try_lock().unwrap() += 1;
                yield_now().await;
            }
        ));

        assert!(poll(&mut join_fut).is_none());
        assert_eq!(*val1.try_lock().unwrap(), 1);
        assert_eq!(*val2.try_lock().unwrap(), 2);

        assert!(poll(&mut join_fut).is_none());
        assert_eq!(*val1.try_lock().unwrap(), 2);
        assert_eq!(*val2.try_lock().unwrap(), 3);

        assert!(poll(&mut join_fut).is_none());
        assert_eq!(*val1.try_lock().unwrap(), 2);
        assert_eq!(*val2.try_lock().unwrap(), 4);

        assert!(poll(&mut join_fut).is_some());
    }

    #[test]
    fn test_select() {
        let val1 = Mutex::new(0);
        let val2 = Mutex::new(1);

        let mut select_fut = pin!(select(
            async {
                *val1.try_lock().unwrap() += 1;
                yield_now().await;
                *val1.try_lock().unwrap() += 1;
                yield_now().await;
            },
            async {
                *val2.try_lock().unwrap() += 1;
                yield_now().await;
                *val2.try_lock().unwrap() += 1;
                yield_now().await;
                *val2.try_lock().unwrap() += 1;
                yield_now().await;
            }
        ));

        assert!(poll(&mut select_fut).is_none());
        assert_eq!(*val1.try_lock().unwrap(), 1);
        assert_eq!(*val2.try_lock().unwrap(), 2);

        assert!(poll(&mut select_fut).is_none());
        assert_eq!(*val1.try_lock().unwrap(), 2);
        assert_eq!(*val2.try_lock().unwrap(), 3);

        let (lhs, rhs) = poll(&mut select_fut).unwrap();
        assert!(lhs.is_some());
        assert!(rhs.is_none());
    }

    #[test]
    fn test_assert_return() {
        // Finishes. No assert.
        block_on(assert_return(async { yield_now().await }));
    }

    #[test]
    #[should_panic]
    fn test_assert_return_panics() {
        let mut fut = pin!(assert_return(async { yield_now().await }));
        // Need one more poll to finish. Thus it should panic when going out of scope.
        assert!(poll(&mut fut).is_none());
    }
}
