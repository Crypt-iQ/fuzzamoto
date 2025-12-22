use fuzzamoto::{
    connections::{Transport, V1Transport},
    fuzzamoto_main,
    runners::Runner,
    scenarios::{Scenario, ScenarioInput, ScenarioResult, generic::GenericScenario},
    targets::{BitcoinCoreTarget, Target},
};

use std::io::Write;
use std::path::PathBuf;

struct WalletDotDatBytes<'a>(&'a [u8]);

impl<'a> ScenarioInput<'a> for WalletDotDatBytes<'a> {
    fn decode(bytes: &'a [u8]) -> Result<Self, String> {
        Ok(WalletDotDatBytes(bytes))
    }
}

/// `WalletMigrationScenario` is a scenario that tests Bitcoin Core's `migratewallet` RPC command.
///
/// Testcases represent wallet.dat files to be migrated. All the scenario does is place the given
/// wallet.dat file in the default wallet directory and call the `migratewallet` RPC command.
struct WalletMigrationScenario<TX: Transport, T: Target<TX>> {
    inner: GenericScenario<TX, T>,
    wallet_path: PathBuf,
}

impl<'a> Scenario<'a, WalletDotDatBytes<'a>>
    for WalletMigrationScenario<V1Transport, BitcoinCoreTarget>
{
    fn new(args: &[String]) -> Result<Self, String> {
        let inner = GenericScenario::<V1Transport, BitcoinCoreTarget>::new(args)?;

        let _ = inner
            .target
            .node
            .client
            .call::<serde_json::Value>("unloadwallet", &["default".into()]);
        let wallet_path = inner
            .target
            .node
            .workdir()
            .join("regtest")
            .join("wallets")
            .join("default");
        let _ = std::fs::remove_dir_all(&wallet_path);

        Ok(Self {
            inner,
            wallet_path: wallet_path.join("wallet.dat"),
        })
    }

    fn run(&mut self, input: WalletDotDatBytes, _runner: &dyn Runner) -> ScenarioResult {
        let _ = std::fs::create_dir_all(self.wallet_path.parent().unwrap());

        if let Ok(mut wallet_file) = std::fs::File::create(&self.wallet_path) {
            let _ = wallet_file.write_all(input.0);
            let _ = wallet_file.flush();

            let _ = self
                .inner
                .target
                .node
                .client
                .call::<serde_json::Value>("migratewallet", &["default".into()]);
        }

        if let Err(e) = self.inner.target.is_alive() {
            return ScenarioResult::Fail(format!("Target is not alive: {}", e));
        }

        ScenarioResult::Ok
    }
}

fuzzamoto_main!(
    WalletMigrationScenario::<fuzzamoto::connections::V1Transport, BitcoinCoreTarget>,
    WalletDotDatBytes
);
