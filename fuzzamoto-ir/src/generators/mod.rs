pub mod add_connection;
pub mod address;
pub mod advance_time;
pub mod block;
pub mod block_txn;
pub mod bloom_filter;
pub mod compact_block;
pub mod compact_filters;
pub mod getaddr;
pub mod getdata;
pub mod send_raw_message;
pub mod tx;
pub mod txo;
pub mod witness;

pub use add_connection::*;
pub use address::*;
pub use advance_time::*;
pub use block::*;
pub use block_txn::*;
pub use bloom_filter::*;
pub use compact_block::*;
pub use compact_filters::*;
pub use getaddr::*;
pub use getdata::*;
pub use send_raw_message::*;
pub use tx::*;
pub use txo::*;
pub use witness::*;

use crate::{
    InstructionContext, PerTestcaseMetadata, Program, ProgramBuilder, ProgramContext,
    ProgramValidationError,
};
use rand::RngCore;

#[derive(Debug, Clone)]
pub enum GeneratorError {
    GeneratedInvalidProgram(ProgramValidationError),
    InvalidContext(ProgramContext),
    MissingVariables,
}

pub type GeneratorResult = Result<(), GeneratorError>;
pub trait Generator<R: RngCore> {
    /// Generate additional instructions into the program being build by `builder`
    fn generate(
        &self,
        builder: &mut ProgramBuilder,
        rng: &mut R,
        meta: Option<&PerTestcaseMetadata>,
    ) -> GeneratorResult;

    /// Name of the generator
    fn name(&self) -> &'static str;

    /// Whether this generator should only run as the first sub-mutation of a scheduled mutation
    /// stack (`idx == 0`), i.e. when runtime metadata is available and no prior sub-mutation has
    /// modified the program this step. Transaction-producing generators return `true` so that a
    /// later sub-mutation cannot invalidate the outputs/ordering they rely on. The gate is applied
    /// by the `IrGenerator` mutator, which is the only place the sub-mutation index is known.
    ///
    /// Note: this does not affect CLI seed generation, which drives generators directly rather
    /// than through the mutator.
    fn requires_metadata(&self) -> bool {
        false
    }

    /// `InstructionContext` the generator expects to generate code in
    fn requested_context(&self) -> InstructionContext {
        InstructionContext::Global
    }

    /// Choose an index in the program where to insert generated instructions
    ///
    /// By default, this selects a random instruction index matching the requested context. Should
    /// be overridden if a different behavior increases the effectiveness of the generator (e.g. to
    /// find indices at which required variables are in scope)
    fn choose_index(
        &self,
        program: &Program,
        rng: &mut R,
        _meta: Option<&mut PerTestcaseMetadata>,
    ) -> Option<usize> {
        program.get_random_instruction_index(rng, &self.requested_context())
    }
}
