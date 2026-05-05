use core::{marker::PhantomData};

use libafl::{
    Error,
    executors::{Executor, ExitKind},
    inputs::HasTargetBytes,
    observers::{ObserversTuple},
    state::HasExecutions,
};

use nyx_lite::NyxVM;

use std::time::Duration;

pub struct NyxLiteExecutor<S, OT> {
    //
    vm: NyxVM,

    // TODO: StdOutObserver
    //

    //
    phantom: PhantomData<S, OT>,
}

impl NyxLiteExecutor {
    pub fn new(vm: NyxVM) -> NyxLiteExecutor {
        Self { vm }
    }
}

impl<EM, I, OT, S, Z> Executor<EM, I, S, Z> for NyxLiteExecutor<S, OT>
where
    S: HasExecutions,
    I: HasTargetBytes,
    OT: ObserversTuple<I, S>,
{
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut S,
        _mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        log::info!("NyxLiteExecutor::run_target");

        // TEST
        let timeout = Duration::from_secs(1);
        let _exit_reason = self.vm.run(timeout);

        // vm.apply_snapshot
        // set input in shared memory
        // exec -> exit value
        Ok(ExitKind::Ok) 
    }
}
