use crate::{
    IndexedVariable, MempoolOutput, MempoolTxo, Operation, PerTestcaseMetadata, TaprootLeafSpec, Variable,
    generators::{Generator, ProgramBuilder},
};
use bitcoin::{
    opcodes::{
        OP_TRUE,
        all::{OP_CHECKSIG, OP_PUSHNUM_1},
    },
    taproot::LeafVersion,
};
use rand::{Rng, RngCore, seq::SliceRandom};
use std::marker::PhantomData;

use super::{GeneratorError, GeneratorResult};

enum OutputType {
    PayToWitnessScriptHash,
    PayToScriptHash,
    PayToAnchor,
    PayToPubKey,
    PayToPubKeyHash,
    PayToWitnessPubKeyHash,
    PayToTaproot,
    OpReturn,
}

fn get_random_output_type<R: RngCore>(rng: &mut R) -> OutputType {
    match rng.gen_range(0..8) {
        0 => OutputType::PayToWitnessScriptHash,
        1 => OutputType::PayToAnchor,
        2 => OutputType::PayToScriptHash,
        3 => OutputType::PayToPubKey,
        4 => OutputType::PayToPubKeyHash,
        5 => OutputType::PayToWitnessPubKeyHash,
        6 => OutputType::PayToTaproot,
        _ => OutputType::OpReturn,
    }
}

fn build_outputs<R: RngCore>(
    builder: &mut ProgramBuilder,
    rng: &mut R,
    mut_outputs_var: &IndexedVariable,
    output_amounts: &[(u64, OutputType)],
    coinbase: bool,
) {
    for (amount, output_type) in output_amounts {
        let scripts_var = match output_type {
            OutputType::PayToWitnessScriptHash => {
                let optrue_bytes_var = builder.force_append_expect_output(
                    vec![],
                    &Operation::LoadBytes(vec![OP_TRUE.to_u8()]),
                );
                let mut_witness_stack_var =
                    builder.force_append_expect_output(vec![], &Operation::BeginWitnessStack);

                let witness_stack_var = builder.force_append_expect_output(
                    vec![mut_witness_stack_var.index],
                    &Operation::EndWitnessStack,
                );

                builder.force_append_expect_output(
                    vec![optrue_bytes_var.index, witness_stack_var.index],
                    &Operation::BuildPayToWitnessScriptHash,
                )
            }
            OutputType::PayToAnchor => {
                builder.force_append_expect_output(vec![], &Operation::BuildPayToAnchor)
            }
            OutputType::OpReturn => {
                let size_var =
                    builder.force_append_expect_output(vec![], &Operation::LoadSize(2 << 15));
                builder.force_append_expect_output(
                    vec![size_var.index],
                    &Operation::BuildOpReturnScripts,
                )
            }
            OutputType::PayToScriptHash => {
                let optrue_bytes_var = builder.force_append_expect_output(
                    vec![],
                    &Operation::LoadBytes(vec![OP_TRUE.to_u8()]),
                );
                let mut_witness_stack_var =
                    builder.force_append_expect_output(vec![], &Operation::BeginWitnessStack);

                let witness_stack_var = builder.force_append_expect_output(
                    vec![mut_witness_stack_var.index],
                    &Operation::EndWitnessStack,
                );

                builder.force_append_expect_output(
                    vec![optrue_bytes_var.index, witness_stack_var.index],
                    &Operation::BuildPayToScriptHash,
                )
            }
            OutputType::PayToPubKey
            | OutputType::PayToPubKeyHash
            | OutputType::PayToWitnessPubKeyHash => {
                let private_key_var = builder
                    .force_append_expect_output(vec![], &Operation::LoadPrivateKey([0x41u8; 32]));
                let sighash_flags_var =
                    builder.force_append_expect_output(vec![], &Operation::LoadSigHashFlags(0));

                let op = match output_type {
                    OutputType::PayToPubKey => Operation::BuildPayToPubKey,
                    OutputType::PayToPubKeyHash => Operation::BuildPayToPubKeyHash,
                    OutputType::PayToWitnessPubKeyHash => Operation::BuildPayToWitnessPubKeyHash,
                    _ => unreachable!(),
                };

                builder.force_append_expect_output(
                    vec![private_key_var.index, sighash_flags_var.index],
                    &op,
                )
            }
            OutputType::PayToTaproot => build_taproot_scripts(builder, rng),
        };

        let amount_var =
            builder.force_append_expect_output(vec![], &Operation::LoadAmount(*amount));

        let add_operation = if coinbase {
            Operation::AddCoinbaseTxOutput
        } else {
            Operation::AddTxOutput
        };

        builder.force_append(
            vec![mut_outputs_var.index, scripts_var.index, amount_var.index],
            &add_operation,
        );
    }
}

fn build_tx<R: RngCore>(
    builder: &mut ProgramBuilder,
    rng: &mut R,
    funding_txos: &[IndexedVariable],
    tx_version: u32,
    output_amounts: &[(u64, OutputType)],
) -> (IndexedVariable, Vec<IndexedVariable>) {
    let tx_version_var =
        builder.force_append_expect_output(vec![], &Operation::LoadTxVersion(tx_version));

    let tx_lock_time_var = builder.force_append_expect_output(vec![], &Operation::LoadLockTime(0));
    let mut_tx_var = builder.force_append_expect_output(
        vec![tx_version_var.index, tx_lock_time_var.index],
        &Operation::BeginBuildTx,
    );
    let mut_inputs_var = builder.force_append_expect_output(vec![], &Operation::BeginBuildTxInputs);

    for funding_txo in funding_txos {
        let sequence_var =
            builder.force_append_expect_output(vec![], &Operation::LoadSequence(0xffff_ffff));
        builder.force_append(
            vec![mut_inputs_var.index, funding_txo.index, sequence_var.index],
            &Operation::AddTxInput,
        );
    }

    let inputs_var = builder
        .force_append_expect_output(vec![mut_inputs_var.index], &Operation::EndBuildTxInputs);

    let mut_outputs_var =
        builder.force_append_expect_output(vec![inputs_var.index], &Operation::BeginBuildTxOutputs);

    build_outputs(builder, rng, &mut_outputs_var, output_amounts, false);

    let outputs_var = builder
        .force_append_expect_output(vec![mut_outputs_var.index], &Operation::EndBuildTxOutputs);

    let const_tx_var = builder.force_append_expect_output(
        vec![mut_tx_var.index, inputs_var.index, outputs_var.index],
        &Operation::EndBuildTx,
    );

    // Make every output of the transaction spendable
    let mut outputs = Vec::new();
    for (_, output_type) in output_amounts {
        let mut txo_var =
            builder.force_append_expect_output(vec![const_tx_var.index], &Operation::TakeTxo);
        if matches!(output_type, OutputType::PayToTaproot) && rng.gen_bool(0.5) {
            let annex_var = builder.force_append_expect_output(
                vec![],
                &Operation::LoadTaprootAnnex {
                    annex: random_annex(rng),
                },
            );
            txo_var = builder.force_append_expect_output(
                vec![txo_var.index, annex_var.index],
                &Operation::TaprootTxoUseAnnex,
            );
        }
        outputs.push(txo_var);
    }

    (const_tx_var, outputs)
}

/// Resolve funding UTXOs, preferring coins the node has actually validated.
///
/// `builder.get_random_utxos` treats every `LoadTxo` and `TakeTxo` output as spendable. But a
/// `TakeTxo` output is only spendable if the node accepted its parent transaction; outputs of
/// rejected transactions become "phantom" UTXOs that fund descendants the node rejects with
/// `bad-txns-inputs-missingorspent` — a dominant reason mempool-size feedback plateaus.
///
/// With probe metadata available, fund only from (a) `LoadTxo` outputs (seed coinbases, always
/// valid) and (b) `TakeTxo` outputs whose parent transaction is in the probed mempool (validated),
/// each validated against the builder's live variable space. If metadata is absent (seed
/// generation) or yields no validated coins, fall back to the unfiltered pool so bootstrapping
/// still works.
fn validated_utxos<R: RngCore>(
    builder: &mut ProgramBuilder,
    rng: &mut R,
    meta: Option<&PerTestcaseMetadata>,
) -> Vec<IndexedVariable> {
    let Some(meta) = meta else {
        return builder.get_random_utxos(rng);
    };

    // Gather candidate mempool outputs (flattened across mempool txs).
    let mut candidates: Vec<&MempoolOutput> = Vec::new();
    for entry in &meta.txo_metadata().txo_entry {
        for out in &entry.outputs {
            candidates.push(out);
        }
    }
    let mempool_total = meta.txo_metadata().txo_entry.len();

    if candidates.is_empty() {
        log::info!(
            "[gate-dbg] validated_utxos: mempool_candidates=0 fallback=true (pool_total={})",
            builder.count_all_utxos()
        );
        return builder.get_random_utxos(rng);
    }

    // Emit a `LoadTxo` for each of a random subset of mempool outputs. A `LoadTxo` declares the
    // coin by raw outpoint/value/scripts, so the resulting Txo variable is always in scope at the
    // insertion point — no dependency on a program-relative variable index.
    let n = rng.gen_range(1..=candidates.len().min(32));
    let chosen: Vec<MempoolOutput> = candidates
        .choose_multiple(rng, n)
        .map(|o| (*o).clone())
        .collect();

    let mut funding = Vec::new();
    for out in &chosen {
        let v = builder.force_append_expect_output(
            vec![],
            &Operation::LoadTxo {
                outpoint: out.outpoint,
                value: out.value,
                script_pubkey: out.script_pubkey.clone(),
                spending_script_sig: out.spending_script_sig.clone(),
                spending_witness: out.spending_witness.clone(),
            },
        );
        funding.push(v);
    }

    log::info!(
        "[gate-dbg] validated_utxos: mempool_txs={mempool_total} candidates={} loaded={} pool_total={}",
        candidates.len(),
        funding.len(),
        builder.count_all_utxos()
    );

    funding
}

/// Resolve the set of funding txos a pool-based transaction generator should spend.
///
/// Funds from the builder's own in-scope UTXO pool via `get_random_utxos`, which includes the
/// pre-created seed UTXOs (so the mempool can bootstrap from an empty state) as well as outputs
/// created earlier in the same program. This is used in both the CLI seed-generation context
/// (where no runtime metadata exists) and during fuzzing.
///
/// The "only fire as the first sub-mutation of a scheduled stack" gate is NOT enforced here — it
/// lives in the `IrGenerator` mutator via `Generator::requires_metadata`, because only the mutator
/// layer knows the sub-mutation index. Enforcing it here (by keying on `meta.is_none()`) would
/// also break CLI seed generation, which always passes `meta == None`.
fn resolve_funding_txos<R: RngCore>(
    builder: &mut ProgramBuilder,
    rng: &mut R,
    meta: Option<&PerTestcaseMetadata>,
) -> Result<Vec<IndexedVariable>, GeneratorError> {
    let funding_txos = validated_utxos(builder, rng, meta);
    log::debug!(
        "[gate-dbg] resolve_funding_txos: validated_utxos returned {} txos (meta={})",
        funding_txos.len(),
        meta.is_some()
    );
    if funding_txos.is_empty() {
        log::debug!("[gate-dbg] resolve_funding_txos: EMPTY -> MissingVariables (no spendable UTXOs)");
        return Err(GeneratorError::MissingVariables);
    }
    Ok(funding_txos)
}

/// Choose an insertion index for a transaction generator such that at least one spendable `Txo`
/// already exists in the program prefix before the insertion point.
///
/// Transaction generators fund from the builder's in-scope UTXO pool (`get_random_utxos`), which is
/// populated only by `LoadTxo` / `TakeTxo` / `TakeCoinbaseTxo` instructions. If a generator is
/// inserted before any such instruction, it has nothing to spend and fails. Rather than pinning
/// these generators to the front of the program (which prevents them from ever seeing a UTXO
/// produced later, e.g. by `TxoGenerator`), anchor the insertion *after* a randomly chosen
/// UTXO-defining instruction. Returns `None` when the program contains no UTXO yet, in which case
/// the generator simply does not run this time.
fn choose_index_after_utxo<R: RngCore>(
    program: &crate::Program,
    rng: &mut R,
    context: &crate::InstructionContext,
) -> Option<usize> {
    let utxo_instrs: Vec<usize> = program
        .instructions
        .iter()
        .enumerate()
        .filter(|(_, instr)| {
            matches!(
                instr.operation,
                Operation::LoadTxo { .. } | Operation::TakeTxo | Operation::TakeCoinbaseTxo
            )
        })
        .map(|(i, _)| i)
        .collect();

    // Anchor after a random UTXO-defining instruction, then take a valid insertion index at or
    // beyond that point (respecting the generator's required context).
    let anchor = *utxo_instrs.choose(rng)?;
    program.get_random_instruction_index_from(rng, context, anchor + 1)
}

/// `SingleTxGenerator` generates instructions for a single new transaction into a program
#[derive(Default)]
pub struct SingleTxGenerator;

impl<R: RngCore> Generator<R> for SingleTxGenerator {
    fn generate(
        &self,
        builder: &mut ProgramBuilder,
        rng: &mut R,
        meta: Option<&PerTestcaseMetadata>,
    ) -> GeneratorResult {
        let funding_txos = resolve_funding_txos(builder, rng, meta)?;

        let tx_version = *[1, 2, 3].choose(rng).unwrap();
        let output_amounts = {
            let mut amounts = vec![];
            let num_outputs = rng.gen_range(1..(funding_txos.len() + 5));
            for _i in 0..num_outputs {
                amounts.push((
                    rng.gen_range(5000..100_000_000),
                    get_random_output_type(rng),
                ));
            }
            amounts
        };
        let (const_tx_var, _) = build_tx(builder, rng, &funding_txos, tx_version, &output_amounts);

        if rng.gen_bool(0.5) {
            let conn_var = builder.get_or_create_random_connection(rng);

            let mut_inventory_var =
                builder.force_append_expect_output(vec![], &Operation::BeginBuildInventory);
            builder.force_append(
                vec![mut_inventory_var.index, const_tx_var.index],
                &Operation::AddWtxidInv,
            );
            let const_inventory_var = builder.force_append_expect_output(
                vec![mut_inventory_var.index],
                &Operation::EndBuildInventory,
            );

            builder.force_append(
                vec![conn_var.index, const_inventory_var.index],
                &Operation::SendInv,
            );
            builder.force_append(vec![conn_var.index, const_tx_var.index], &Operation::SendTx);
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "SingleTxGenerator"
    }

    fn choose_index(
        &self,
        program: &crate::Program,
        rng: &mut R,
        _meta: Option<&mut PerTestcaseMetadata>,
    ) -> Option<usize> {
        // Run after a UTXO exists in the program (e.g. a `LoadTxo` produced by `TxoGenerator`),
        // so there is something to fund the transaction from.
        choose_index_after_utxo(program, rng, &<Self as Generator<R>>::requested_context(self))
    }
}

/// `OneParentOneChildGenerator` generates instructions for creating a 1P1C package and sending it
/// to a node, with the child tx being the first to be sent
#[derive(Default)]
pub struct OneParentOneChildGenerator;

impl<R: RngCore> Generator<R> for OneParentOneChildGenerator {
    fn generate(
        &self,
        builder: &mut ProgramBuilder,
        rng: &mut R,
        meta: Option<&PerTestcaseMetadata>,
    ) -> GeneratorResult {
        let funding_txos = resolve_funding_txos(builder, rng, meta)?;

        let (parent_tx_var, parent_output_vars) = build_tx(
            builder,
            rng,
            &funding_txos,
            2,
            &[
                (100_000_000, OutputType::PayToWitnessScriptHash),
                (10000, OutputType::PayToAnchor),
            ],
        );
        let (child_tx_var, _) = build_tx(
            builder,
            rng,
            &[parent_output_vars.last().unwrap().clone()],
            2,
            &[(50_000_000, OutputType::PayToWitnessScriptHash)],
        );

        let conn_var = builder.get_or_create_random_connection(rng);

        let mut send_tx = |tx_var: IndexedVariable| {
            let mut_inventory_var =
                builder.force_append_expect_output(vec![], &Operation::BeginBuildInventory);
            builder.force_append(
                vec![mut_inventory_var.index, tx_var.index],
                &Operation::AddWtxidInv,
            );
            let const_inventory_var = builder.force_append_expect_output(
                vec![mut_inventory_var.index],
                &Operation::EndBuildInventory,
            );

            builder.force_append(
                vec![conn_var.index, const_inventory_var.index],
                &Operation::SendInv,
            );

            builder.force_append(vec![conn_var.index, tx_var.index], &Operation::SendTx);
        };
        // Send the child tx first to trigger 1p1c logic
        send_tx(child_tx_var);
        send_tx(parent_tx_var);

        Ok(())
    }

    fn name(&self) -> &'static str {
        "1P1CGenerator"
    }

    fn choose_index(
        &self,
        program: &crate::Program,
        rng: &mut R,
        _meta: Option<&mut PerTestcaseMetadata>,
    ) -> Option<usize> {
        // Run after a UTXO exists in the program (e.g. a `LoadTxo` produced by `TxoGenerator`),
        // so there is something to fund the transaction from.
        choose_index_after_utxo(program, rng, &<Self as Generator<R>>::requested_context(self))
    }
}

/// `LongChainGenerator` generates instructions for creating a chain of 25 transactions and sending
/// them to a node
#[derive(Default)]
pub struct LongChainGenerator;

impl<R: RngCore> Generator<R> for LongChainGenerator {
    fn generate(
        &self,
        builder: &mut ProgramBuilder,
        rng: &mut R,
        meta: Option<&PerTestcaseMetadata>,
    ) -> GeneratorResult {
        let mut funding_txos = resolve_funding_txos(builder, rng, meta)?;

        // Create a chain of 25 transactions (default ancestor limit in Bitcoin Core), where each
        // transaction spends the output of the previous transaction
        let mut tx_vars = Vec::new();
        for i in 0..25 {
            let (tx_var, outputs) = build_tx(
                builder,
                rng,
                &funding_txos,
                2,
                &[(
                    100_000_000 - (i * 100_000),
                    OutputType::PayToWitnessScriptHash,
                )],
            );
            tx_vars.push(tx_var);
            funding_txos = outputs;
        }

        let conn_var = builder.get_or_create_random_connection(rng);

        // Send the transactions to the network
        for tx_var in tx_vars {
            let mut_inventory_var =
                builder.force_append_expect_output(vec![], &Operation::BeginBuildInventory);
            builder.force_append(
                vec![mut_inventory_var.index, tx_var.index],
                &Operation::AddWtxidInv,
            );
            let const_inventory_var = builder.force_append_expect_output(
                vec![mut_inventory_var.index],
                &Operation::EndBuildInventory,
            );

            builder.force_append(
                vec![conn_var.index, const_inventory_var.index],
                &Operation::SendInv,
            );
            builder.force_append(vec![conn_var.index, tx_var.index], &Operation::SendTx);
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "LongChainGenerator"
    }

    fn choose_index(
        &self,
        program: &crate::Program,
        rng: &mut R,
        _meta: Option<&mut PerTestcaseMetadata>,
    ) -> Option<usize> {
        // Run after a UTXO exists in the program (e.g. a `LoadTxo` produced by `TxoGenerator`),
        // so there is something to fund the transaction from.
        choose_index_after_utxo(program, rng, &<Self as Generator<R>>::requested_context(self))
    }
}

/// `LargeTxGenerator` generates instructions for creating a single large transaction and sending
/// it to a node
#[derive(Default)]
pub struct LargeTxGenerator;

impl<R: RngCore> Generator<R> for LargeTxGenerator {
    fn generate(
        &self,
        builder: &mut ProgramBuilder,
        rng: &mut R,
        meta: Option<&PerTestcaseMetadata>,
    ) -> GeneratorResult {
        let funding_txos = resolve_funding_txos(builder, rng, meta)?;

        let conn_var = builder.get_or_create_random_connection(rng);

        for utxo in funding_txos {
            let (tx_var, _) = build_tx(
                builder,
                rng,
                std::slice::from_ref(&utxo),
                2,
                &[(10_000, OutputType::OpReturn)],
            );

            let mut send_tx = |tx_var: IndexedVariable| {
                let mut_inventory_var =
                    builder.force_append_expect_output(vec![], &Operation::BeginBuildInventory);
                builder.force_append(
                    vec![mut_inventory_var.index, tx_var.index],
                    &Operation::AddWtxidInv,
                );
                let const_inventory_var = builder.force_append_expect_output(
                    vec![mut_inventory_var.index],
                    &Operation::EndBuildInventory,
                );

                builder.force_append(
                    vec![conn_var.index, const_inventory_var.index],
                    &Operation::SendInv,
                );
                builder.force_append(vec![conn_var.index, tx_var.index], &Operation::SendTx);
            };
            send_tx(tx_var);
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "LargeTxGenerator"
    }

    fn choose_index(
        &self,
        program: &crate::Program,
        rng: &mut R,
        _meta: Option<&mut PerTestcaseMetadata>,
    ) -> Option<usize> {
        // Run after a UTXO exists in the program (e.g. a `LoadTxo` produced by `TxoGenerator`),
        // so there is something to fund the transaction from.
        choose_index_after_utxo(program, rng, &<Self as Generator<R>>::requested_context(self))
    }
}

/// `PredicateTxGenerator` generates a transaction that spends a transaction currently in the
/// node's mempool, selected by a predicate over the probed `MempoolTxo` entries.
///
/// Unlike the pool-based generators, this one funds exclusively from txos the node actually
/// accepted (the probed mempool), so it never spends IR-structural phantom outputs. The
/// `choose_index` override anchors the insertion point *after* the instruction that defines the
/// chosen txo, so the funded transaction still exists in the mutated program.
pub struct PredicateTxGenerator<F> {
    predicate: F,
    phantom: PhantomData<F>,
}

impl<F, R: RngCore> Generator<R> for PredicateTxGenerator<F>
where
    F: Fn(&MempoolTxo) -> bool,
{
    fn generate(
        &self,
        builder: &mut ProgramBuilder,
        rng: &mut R,
        meta: Option<&PerTestcaseMetadata>,
    ) -> GeneratorResult {
        let Some(meta) = meta else {
            log::debug!("[gate-dbg] Predicate::generate: meta=None -> skip");
            return Err(GeneratorError::MissingVariables);
        };
        if meta.txo_metadata().txo_entry.is_empty() {
            log::debug!("[gate-dbg] Predicate::generate: mempool txo_entry EMPTY -> skip");
            return Err(GeneratorError::MissingVariables);
        }

        let Some(chosen) = meta.txo_metadata().choice else {
            // `choose_index` did not select a txo (no entry satisfied the predicate).
            log::debug!("[gate-dbg] Predicate::generate: choice=None -> skip");
            return Err(GeneratorError::MissingVariables);
        };
        let Some(entry) = meta.txo_metadata().txo_entry.get(chosen) else {
            log::debug!("[gate-dbg] Predicate::generate: chosen index {chosen} out of range -> skip");
            return Err(GeneratorError::MissingVariables);
        };
        log::debug!(
            "[gate-dbg] Predicate::generate: spending mempool txo (var={}, inst={})",
            entry.definition.0,
            entry.definition.1
        );

        // `entry.definition.0` is a variable index captured at probe/compile time. The builder
        // here holds only the mutation prefix, so that index is only usable if it currently
        // resolves to an in-scope `Txo` in *this* builder. Validate it via `get_variable` (which
        // checks existence, scope, and type) and skip rather than fabricate an index — passing an
        // unresolved/mistyped index to `build_tx` makes `AddTxInput`'s `force_append` panic.
        let Some(funding_txo) = builder.get_variable(entry.definition.0) else {
            log::debug!(
                "[gate-dbg] Predicate::generate: funding var {} not in scope in builder -> skip",
                entry.definition.0
            );
            return Err(GeneratorError::MissingVariables);
        };
        if !matches!(funding_txo.var, Variable::Txo) {
            log::debug!(
                "[gate-dbg] Predicate::generate: funding var {} is not a Txo ({:?}) -> skip",
                entry.definition.0,
                funding_txo.var
            );
            return Err(GeneratorError::MissingVariables);
        }

        let tx_version = *[1, 2, 3].choose(rng).unwrap();
        let output_amounts = [(
            rng.gen_range(5000..100_000_000),
            get_random_output_type(rng),
        )];
        let (const_tx_var, _) = build_tx(
            builder,
            rng,
            std::slice::from_ref(&funding_txo),
            tx_version,
            &output_amounts,
        );

        let conn_var = builder.get_or_create_random_connection(rng);

        let mut_inventory_var =
            builder.force_append_expect_output(vec![], &Operation::BeginBuildInventory);
        builder.force_append(
            vec![mut_inventory_var.index, const_tx_var.index],
            &Operation::AddWtxidInv,
        );
        let const_inventory_var = builder
            .force_append_expect_output(vec![mut_inventory_var.index], &Operation::EndBuildInventory);

        builder.force_append(
            vec![conn_var.index, const_inventory_var.index],
            &Operation::SendInv,
        );
        builder.force_append(vec![conn_var.index, const_tx_var.index], &Operation::SendTx);

        Ok(())
    }

    fn choose_index(
        &self,
        program: &crate::Program,
        rng: &mut R,
        meta: Option<&mut PerTestcaseMetadata>,
    ) -> Option<usize> {
        let meta = meta?;
        let filtered = meta
            .txo_metadata()
            .txo_entry
            .iter()
            .enumerate()
            .filter(|(_, x)| (self.predicate)(x))
            .map(|(idx, entry)| (idx, entry.definition.1))
            .collect::<Vec<_>>();

        let (chosen_idx, defining_instruction) = *filtered.choose(rng)?;
        meta.txo_metadata_mut().choice = Some(chosen_idx);
        program.get_random_instruction_index_from(
            rng,
            &<Self as Generator<R>>::requested_context(self),
            defining_instruction + 1,
        )
    }

    fn name(&self) -> &'static str {
        "PredicateTxGenerator"
    }

    fn requires_metadata(&self) -> bool {
        true
    }
}

impl<F> PredicateTxGenerator<F> {
    #[must_use]
    pub fn new(predicate: F) -> Self {
        Self {
            predicate,
            phantom: PhantomData,
        }
    }
}

impl PredicateTxGenerator<fn(&MempoolTxo) -> bool> {
    /// Spend a mempool txo that is already spent by another mempool tx (exercises RBF / conflicts).
    #[must_use]
    pub fn double_spend() -> Self {
        Self {
            predicate: |x: &MempoolTxo| !x.spentby.is_empty(),
            phantom: PhantomData,
        }
    }

    /// Spend a mempool txo with no in-mempool ancestors (extends fresh chains).
    #[must_use]
    pub fn chain_spend() -> Self {
        Self {
            predicate: |x: &MempoolTxo| x.depends.is_empty(),
            phantom: PhantomData,
        }
    }

    /// Spend any mempool txo.
    #[must_use]
    pub fn any() -> Self {
        Self {
            predicate: |_: &MempoolTxo| true,
            phantom: PhantomData,
        }
    }
}

/// `CoinbaseTxGenerator` generates instructions for a coinbase tx into a program
#[derive(Default)]
pub struct CoinbaseTxGenerator;

impl<R: RngCore> Generator<R> for CoinbaseTxGenerator {
    fn generate(
        &self,
        builder: &mut ProgramBuilder,
        rng: &mut R,
        _meta: Option<&PerTestcaseMetadata>,
    ) -> GeneratorResult {
        let tx_version_var =
            builder.force_append_expect_output(vec![], &Operation::LoadTxVersion(1));

        let tx_lock_time_var =
            builder.force_append_expect_output(vec![], &Operation::LoadLockTime(0));

        let mut_tx_var = builder.force_append_expect_output(
            vec![tx_version_var.index, tx_lock_time_var.index],
            &Operation::BeginBuildCoinbaseTx,
        );

        let sequence_var =
            builder.force_append_expect_output(vec![], &Operation::LoadSequence(0xffff_ffff));

        let coinbase_input_var = builder
            .force_append_expect_output(vec![sequence_var.index], &Operation::BuildCoinbaseTxInput);

        let mut_outputs_var = builder.force_append_expect_output(
            vec![coinbase_input_var.index],
            &Operation::BeginBuildCoinbaseTxOutputs,
        );
        let output_amounts = {
            let mut amounts = vec![];
            let num_outputs = rng.gen_range(1..10);
            for _i in 0..num_outputs {
                amounts.push((
                    rng.gen_range(5000..100_000_000),
                    get_random_output_type(rng),
                ));
            }
            amounts
        };

        build_outputs(builder, rng, &mut_outputs_var, &output_amounts, true);

        let outputs_var = builder.force_append_expect_output(
            vec![mut_outputs_var.index],
            &Operation::EndBuildCoinbaseTxOutputs,
        );

        builder.force_append(
            vec![
                mut_tx_var.index,
                coinbase_input_var.index,
                outputs_var.index,
            ],
            &Operation::EndBuildCoinbaseTx,
        );
        Ok(())
    }

    fn name(&self) -> &'static str {
        "CoinbaseTxGenerator"
    }
}

fn build_taproot_scripts<R: RngCore>(builder: &mut ProgramBuilder, rng: &mut R) -> IndexedVariable {
    let secret_key = gen_secret_key_bytes(rng);

    // Key-path only (None) or script-path (Some) with one spendable leaf.
    let script_leaf = if rng.gen_bool(0.5) {
        None
    } else {
        let (version, _) = random_leaf_version(rng);
        let script = random_tapscript(rng);
        let merkle_path = random_merkle_path(rng);
        Some(TaprootLeafSpec {
            script,
            version,
            merkle_path,
        })
    };

    let spend_info_var = builder.force_append_expect_output(
        vec![],
        &Operation::BuildTaprootTree {
            secret_key,
            script_leaf,
        },
    );

    builder.force_append_expect_output(vec![spend_info_var.index], &Operation::BuildPayToTaproot)
}

/// Generate a merkle path to simulate additional leaves in the taproot tree.
fn random_merkle_path<R: RngCore>(rng: &mut R) -> Vec<[u8; 32]> {
    let depth = rng.gen_range(0..=4);
    (0..depth).map(|_| random_node_hash(rng)).collect()
}

fn gen_secret_key_bytes<R: RngCore>(rng: &mut R) -> [u8; 32] {
    loop {
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        if secret.iter().any(|&b| b != 0) {
            return secret;
        }
    }
}

/// Build a short annex payload that satisfies the BIP341 0x50 prefix rule.
fn random_annex<R: RngCore>(rng: &mut R) -> Vec<u8> {
    let extra_len = rng.gen_range(0..=64);
    let mut annex = Vec::with_capacity(1 + extra_len);
    annex.push(0x50);
    for _ in 0..extra_len {
        annex.push(rng.r#gen());
    }
    annex
}

/// Returns a consensus tapleaf version plus a flag indicating whether it is non-default.
fn random_leaf_version<R: RngCore>(rng: &mut R) -> (u8, bool) {
    if rng.gen_bool(0.5) {
        (LeafVersion::TapScript.to_consensus(), false)
    } else {
        (pick_strict_non_default_version(rng), true)
    }
}

fn pick_strict_non_default_version<R: RngCore>(rng: &mut R) -> u8 {
    *[0xC2u8, 0xC4, 0xC6, 0xD0].choose(rng).unwrap()
}

/// Emit lightweight tapscripts so we mix success, CHECKSIG, and `OP_TRUE` leaves.
fn random_tapscript<R: RngCore>(rng: &mut R) -> Vec<u8> {
    match rng.gen_range(0..3) {
        0 => vec![OP_PUSHNUM_1.to_u8()],
        1 => {
            let mut script = Vec::with_capacity(34);
            script.push(32);
            for _ in 0..32 {
                script.push(rng.r#gen());
            }
            script.push(OP_CHECKSIG.to_u8());
            script
        }
        _ => vec![0x50],
    }
}

fn random_node_hash<R: RngCore>(rng: &mut R) -> [u8; 32] {
    let mut hash = [0u8; 32];
    rng.fill_bytes(&mut hash);
    hash
}

#[cfg(test)]
mod gate_tests {
    use super::*;
    use crate::generators::txo::TxoGenerator;
    use crate::{ProgramContext, Txo};
    use rand::SeedableRng;
    use rand::rngs::SmallRng;

    fn ctx() -> ProgramContext {
        ProgramContext {
            num_nodes: 1,
            num_connections: 1,
            timestamp: 0,
        }
    }

    fn seed_txo() -> Txo {
        Txo {
            outpoint: ([1u8; 32], 0),
            value: 25 * 100_000_000,
            script_pubkey: vec![0x51],
            spending_script_sig: vec![],
            spending_witness: vec![vec![0x51]],
        }
    }

    /// Reproduces the CLI seed-generation call: a tx generator invoked with `meta == None` must
    /// still produce instructions (funding from the IR pool), otherwise the initial corpus would
    /// contain no transactions and the mempool could never bootstrap.
    #[test]
    fn tx_generator_produces_instructions_with_none_metadata() {
        let mut rng = SmallRng::seed_from_u64(1);
        let mut builder = ProgramBuilder::new(ctx());

        // Seed a spendable UTXO into the IR pool (as the CLI does via TxoGenerator).
        let txo_gen = TxoGenerator::new(vec![seed_txo()]);
        txo_gen
            .generate(&mut builder, &mut rng, None)
            .expect("TxoGenerator should append a LoadTxo");
        let after_txo = builder.instructions.len();
        assert!(after_txo >= 1, "LoadTxo should have been appended");

        // The exact call the seed generator makes: SingleTxGenerator with meta = None.
        let tx_gen = SingleTxGenerator;
        tx_gen.generate(&mut builder, &mut rng, None)
            .expect("SingleTxGenerator must fund from the IR pool when meta is None");

        assert!(
            builder.instructions.len() > after_txo,
            "SingleTxGenerator should append transaction-building instructions"
        );
    }

    /// All transaction-producing generators are gated: the mutator only runs them as the first
    /// sub-mutation of a stack (where metadata is present and no prior sub-mutation has reordered
    /// or spent their inputs). `StackResetMutator` guarantees the per-stack counter resets so this
    /// gate cannot wedge. Coinbase is not a mempool tx and stays ungated.
    #[test]
    fn tx_generators_require_metadata_flag() {
        // `PredicateTxGenerator` funds from probed mempool metadata, so it must receive metadata
        // (delivered by the mutator only at `is_first`).
        assert!(Generator::<SmallRng>::requires_metadata(
            &PredicateTxGenerator::any()
        ));
        // The pool-based generators fund from in-program UTXOs; they don't need metadata and
        // instead anchor their insertion after a UTXO-defining instruction via `choose_index`,
        // so they can run at any position (e.g. after a `TxoGenerator`-produced `LoadTxo`).
        assert!(!Generator::<SmallRng>::requires_metadata(&SingleTxGenerator));
        assert!(!Generator::<SmallRng>::requires_metadata(
            &OneParentOneChildGenerator
        ));
        assert!(!Generator::<SmallRng>::requires_metadata(
            &LongChainGenerator
        ));
        assert!(!Generator::<SmallRng>::requires_metadata(&LargeTxGenerator));
        // Coinbase is not a mempool tx and is intentionally ungated.
        assert!(!Generator::<SmallRng>::requires_metadata(
            &CoinbaseTxGenerator
        ));
    }
}
