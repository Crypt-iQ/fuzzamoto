use crate::error::{CliError, Result};
use crate::utils::{file_ops, process};
use std::path::PathBuf;

pub struct CoverageCommand;

impl CoverageCommand {
    pub fn execute(
        output: PathBuf,
        corpus: PathBuf,
        bitcoind: PathBuf,
        scenario: PathBuf,
    ) -> Result<()> {
        file_ops::ensure_file_exists(&bitcoind)?;
        file_ops::ensure_file_exists(&scenario)?;

        let corpus_files = file_ops::read_dir_files(&corpus)?;

        // Run scenario for each corpus file
        for corpus_file in corpus_files {
            if let Err(e) = Self::run_one_input(&output, &corpus_file, &bitcoind, &scenario) {
                log::error!("Failed to run input ({:?}): {}", corpus_file, e);
            }
        }

        Self::generate_coverage_report(&output, &bitcoind)?;

        Ok(())
    }

    fn run_one_input(
        output: &PathBuf,
        input: &PathBuf,
        bitcoind: &PathBuf,
        scenario: &PathBuf,
    ) -> Result<()> {
        log::info!("Running scenario with input: {}", input.display());

        let profraw_file = output.join(format!(
            "{}.coverage.profraw.%p",
            input.file_name().unwrap().to_str().unwrap()
        ));

        let env_vars = vec![
            ("LLVM_PROFILE_FILE", profraw_file.to_str().unwrap()),
            ("FUZZAMOTO_INPUT", input.to_str().unwrap()),
            ("RUST_LOG", "debug"),
        ];

        process::run_scenario_command(scenario, bitcoind, &env_vars)?;

        Ok(())
    }

    fn generate_coverage_report(output: &PathBuf, bitcoind: &PathBuf) -> Result<()> {
        // Find all profraw files
        let mut profraw_files = Vec::new();
        for entry in std::fs::read_dir(output)? {
            let path = entry?.path();
            if let Some(file_name) = path.file_name().and_then(|s| s.to_str()) {
                if file_name.contains("coverage.profraw") {
                    profraw_files.push(path.to_str().unwrap().to_string());
                }
            }
        }

        if profraw_files.is_empty() {
            return Err(CliError::ProcessError("No profraw files found".to_string()));
        }

        const chunk_size: usize = 1000;

        let mut coverage_profdata_files = Vec::new();
        for (chunk_index, chunk) in profraw_files.chunks(chunk_size).enumerate() {
            // Merge profraw files
            let coverage_profdata = output.join(format!(
                "coverage{}.profdata",
                chunk_index
            ));
            let coverage_profdata_str = coverage_profdata.to_str().unwrap();
            coverage_profdata_files.push(coverage_profdata_str.to_string());

            let mut merge_args = vec!["merge", "-sparse"];
            let profraw_refs: Vec<&str> = chunk.iter().map(|s| s.as_str()).collect();
            merge_args.extend(profraw_refs);
            merge_args.extend(["-o", coverage_profdata_str]);
            let merge_cmd = process::get_llvm_command("llvm-profdata");
            process::run_command_with_status(&merge_cmd, &merge_args, None)?;
        }

        // Merge coverage*.profdata into coverage.profdata
        let coverage_profdata = output.join("coverage.profdata");
        let coverage_profdata_str = coverage_profdata.to_str().unwrap();
        let mut merge_args = vec!["merge", "-sparse"];
        let profdata_refs: Vec<&str> = coverage_profdata_files.iter().map(|s| s.as_str()).collect();
        merge_args.extend(profdata_refs);
        merge_args.extend(["-o", coverage_profdata_str]);
        let merge_cmd = process::get_llvm_command("llvm-profdata");
        process::run_command_with_status(&merge_cmd, &merge_args, None)?;

        // Generate HTML report
        let coverage_report_dir = output.join("coverage-report");
        let coverage_report_str = coverage_report_dir.to_str().unwrap();
        let instr_profile_arg = format!("-instr-profile={}", coverage_profdata_str);
        let output_dir_arg = format!("-output-dir={}", coverage_report_str);

        let show_args = vec![
            "show",
            bitcoind.to_str().unwrap(),
            &instr_profile_arg,
            "-format=html",
            "-show-directory-coverage",
            "-show-branches=count",
            &output_dir_arg,
            "-Xdemangler=c++filt",
        ];

        let show_cmd = process::get_llvm_command("llvm-cov");
        process::run_command_with_status(&show_cmd, &show_args, None)?;

        log::info!(
            "Coverage report generated in: {}",
            coverage_report_dir.display()
        );

        Ok(())
    }
}
