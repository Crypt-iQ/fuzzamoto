pub mod generic;

use crate::{connections::Transport, targets::Target};

#[cfg(not(feature = "record"))]
use crate::connections::V1Transport;
#[cfg(feature = "record")]
use crate::{connections::RecordingTransport, targets::RecorderTarget};

/// `ScenarioCharacterization` is a trait for characterizing the behavior of a scenario.
pub trait ScenarioCharacterization {
    /// Reduce the result to a 32 byte array (e.g. a hash of the result).
    fn reduce(&self) -> [u8; 32];
}

/// `IgnoredCharacterization` is a type of scenario characterization that is ignored by the fuzzer.
/// Used for scenarios that are not meant to characterize behavior.
pub struct IgnoredCharacterization;
impl ScenarioCharacterization for IgnoredCharacterization {
    fn reduce(&self) -> [u8; 32] {
        [0u8; 32]
    }
}

/// `ScenarioInput` is a trait for scenario input types.
pub trait ScenarioInput<'a>: Sized {
    /// Decode the input from a byte slice.
    fn decode(bytes: &'a [u8]) -> Result<Self, String>;
}

/// `ScenarioResult` describes the various outcomes of running a scenario.
pub enum ScenarioResult<SC: ScenarioCharacterization> {
    /// Scenario ran successfully and the behavior characterization is returned.
    Ok(SC),
    /// Scenario indicated that the test case should be skipped.
    Skip,
    /// Scenario indicated that the test case failed (i.e. the target node crashed).
    Fail(String),
}

/// `Scenario` is the interface for test scenarios that can be run against a target node.
pub trait Scenario<'a, I, SC, TX, T>: Sized
where
    I: ScenarioInput<'a>,
    SC: ScenarioCharacterization,
    TX: Transport,
    T: Target<TX>,
{
    // Create a new instance of the scenario, preparing the initial state of the test
    fn new(target: &mut T) -> Result<Self, String>;
    // Run the test
    fn run(&mut self, target: &mut T, testcase: I) -> ScenarioResult<SC>;
}

#[cfg(feature = "record")]
pub type StdTarget<T> = RecorderTarget<T>;
#[cfg(not(feature = "record"))]
pub type StdTarget<T> = T;

#[cfg(feature = "record")]
pub type StdTransport = RecordingTransport;
#[cfg(not(feature = "record"))]
pub type StdTransport = V1Transport;

pub fn notify_snapshot<T>(_target: &mut StdTarget<T>) {
    #[cfg(feature = "record")]
    _target.take_snapshot();
}

#[macro_export]
macro_rules! fuzzamoto_main {
    ($scenario_type:ident, $target_type:ty, $testcase_type:ty) => {
        fn main() -> std::process::ExitCode {
            use env_logger;
            env_logger::init();

            let args: Vec<String> = std::env::args().collect();
            if args.len() < 2 {
                eprintln!("Usage: {} <bitcoin-core-exe-path>", args[0]);
                return std::process::ExitCode::from(1);
            }

            let runner = fuzzamoto::runners::StdRunner::new();

            log::info!("Starting target...");
            let exe_path = &args[1];

            // Define the target type
            type TargetImpl = fuzzamoto::scenarios::StdTarget<$target_type>;
            let mut target = TargetImpl::new(exe_path).unwrap();

            log::info!("Initializing scenario...");
            // Define the scenario type with the target as its generic parameter
            type ScenarioImpl = $scenario_type<fuzzamoto::scenarios::StdTransport, TargetImpl>;
            let Ok(mut scenario) = ScenarioImpl::new(&mut target) else {
                log::error!("Failed to initialize scenario!");
                let exit_code = std::env::var("FUZZAMOTO_INIT_ERROR_EXIT_CODE")
                    .map_or(0, |v| v.parse().unwrap_or(0));
                return std::process::ExitCode::from(exit_code);
            };

            fuzzamoto::scenarios::notify_snapshot(&mut target);

            // Ensure the runner dropped prior to the target and scenario when returning from main.
            let runner = runner;
            log::info!("Scenario initialized! Running input...");

            // In nyx mode the snapshot is taken here and a new fuzz input is provided each reset.
            let input = runner.get_fuzz_input();

            let Ok(testcase) = <$testcase_type>::decode(&input) else {
                log::warn!("Failed to decode test case!");
                drop(target);
                runner.skip();
                return std::process::ExitCode::SUCCESS;
            };

            match scenario.run(&mut target, testcase) {
                ScenarioResult::Ok(_) => {
                    // drop(target); // Check if there's a way to see whether the VM is restored in both cases.
                    // We can call a method on the runner? Is there a way to intentionally pollute global bitcoind state
                    // to test this?
                    // First see if we can log every iteration?
                    //
                    drop(target);
                    runner.skip();
                }
                ScenarioResult::Skip => {
                    drop(target);
                    runner.skip();
                    return std::process::ExitCode::SUCCESS;
                }
                ScenarioResult::Fail(err) => {
                    runner.fail(&format!("Test case failed: {}", err));
                    return std::process::ExitCode::from(1);
                }
            }

            log::info!("Test case ran successfully!");
            return std::process::ExitCode::SUCCESS;
        }
    };
}
