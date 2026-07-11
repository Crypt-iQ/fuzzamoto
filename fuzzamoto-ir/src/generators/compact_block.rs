use super::{GeneratorError, GeneratorResult};
use crate::{
    Instruction, Operation, PerTestcaseMetadata, Variable,
    generators::{Generator, ProgramBuilder},
};
use rand::{Rng, RngCore, seq::SliceRandom};

/// `CompactBlockGenerator` generates a new `cmpctblock` message.
#[derive(Debug, Default)]
pub struct CompactBlockGenerator;

impl<R: RngCore> Generator<R> for CompactBlockGenerator {
    fn generate(
        &self,
        builder: &mut ProgramBuilder,
        rng: &mut R,
        _meta: Option<&PerTestcaseMetadata>,
    ) -> GeneratorResult {
        // Choose a block upon which we build the compact block
        let Some(block) = builder.get_random_variable(rng, &Variable::Block) else {
            return Err(GeneratorError::MissingVariables);
        };

        let Some(tx_var_indices) = builder.get_block_vars(block.index) else {
            return Err(GeneratorError::MissingVariables);
        };

        // Collect into an owned vec before the loop since we need to call
        // builder.append() which takes &mut self.
        let tx_var_indices: Vec<usize> = tx_var_indices;
        let num_block_txs = tx_var_indices.len();

        let connection_var = builder.get_or_create_random_connection(rng);

        let nonce_var = builder
            .append(Instruction {
                inputs: vec![],
                operation: Operation::LoadNonce(rng.gen_range(0..u64::MAX)),
            })
            .expect("LoadNonce should always succeed")
            .pop()
            .expect("LoadNonce should always produce a var");

        // Build the prefill list dynamically from actual transactions in the block.
        let prefill_list = builder
            .append(Instruction {
                inputs: vec![],
                operation: Operation::BeginPrefillTransactions,
            })
            .expect("BeginPrefillTransactions should always succeed")
            .pop()
            .expect("BeginPrefillTransactions should always produce a var");

        if num_block_txs > 0 {
            // Pick a random number of transactions to prefill, bounded by the
            // actual number of transactions in the block.
            let num_prefill = rng.gen_range(0..=num_block_txs);

            // Half the time shuffle to pick a random subset; otherwise take the
            // first num_prefill in block order for varied coverage.
            let mut shuffled = tx_var_indices.clone();
            if rng.gen_bool(0.5) {
                shuffled.shuffle(rng);
            }

            for tx_idx in shuffled.into_iter().take(num_prefill) {
                builder
                    .append(Instruction {
                        inputs: vec![prefill_list.index, block.index, tx_idx],
                        operation: Operation::AddPrefillTx,
                    })
                    .expect("AddPrefillTx should always succeed");
            }
        }

        let const_prefill = builder
            .append(Instruction {
                inputs: vec![prefill_list.index],
                operation: Operation::EndPrefillTransactions,
            })
            .expect("EndPrefillTransactions should always succeed")
            .pop()
            .expect("EndPrefillTransactions should always produce a var");

        let cmpct_block = builder
            .append(Instruction {
                inputs: vec![block.index, nonce_var.index, const_prefill.index],
                operation: Operation::BuildCompactBlock,
            })
            .expect("BuildCompactBlock should always succeed")
            .pop()
            .expect("BuildCompactBlock should always produce a var");

        builder
            .append(Instruction {
                inputs: vec![connection_var.index, cmpct_block.index],
                operation: Operation::SendCompactBlock,
            })
            .expect("Inserting SendCompactBlock should always succeed");

        Ok(())
    }

    fn name(&self) -> &'static str {
        "CompactBlockGenerator"
    }

    fn choose_index(
        &self,
        program: &crate::Program,
        rng: &mut R,
        _meta: Option<&mut PerTestcaseMetadata>,
    ) -> Option<usize> {
        // Collect valid insertion ranges: after BuildBlock but at or before the corresponding
        // SendBlock, so the compact block is sent before the full block for the same block.
        // Store (start, end) pairs instead of every individual index to avoid O(n) allocations.
        let mut ranges: Vec<(usize, usize)> = Vec::new();
        let mut var_count: usize = 0;

        for (i, instr) in program.instructions.iter().enumerate() {
            if matches!(instr.operation, Operation::BuildBlock) {
                // Block is the second output of BuildBlock (offset 1).
                let block_var_idx = var_count + 1;
                if let Some(send_pos) = program.instructions[i + 1..]
                    .iter()
                    .position(|s| {
                        matches!(s.operation, Operation::SendBlock)
                            && s.inputs.get(1) == Some(&block_var_idx)
                    })
                    .map(|rel| rel + i + 1)
                {
                    ranges.push((i + 1, send_pos));
                }
            }
            var_count += instr.operation.num_outputs() + instr.operation.num_inner_outputs();
        }

        if ranges.is_empty() {
            return None;
        }

        let total: usize = ranges.iter().map(|(s, e)| e - s + 1).sum();
        let mut pick = rng.gen_range(0..total);
        for (start, end) in ranges {
            let len = end - start + 1;
            if pick < len {
                return Some(start + pick);
            }
            pick -= len;
        }
        unreachable!()
    }
}
