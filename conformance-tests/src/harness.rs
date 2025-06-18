use async_trait::async_trait;
use fr_block::types::block::BlockHeader;
use fr_common::utils::tracing::setup_timed_tracing;
use fr_state::{error::StateManagerError, manager::StateManager};
use fr_transition::error::TransitionError;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    fmt::Debug,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TestCase<I, O, S> {
    pub input: I,
    pub pre_state: S,
    pub output: O,
    pub post_state: S,
}

#[async_trait]
pub trait StateTransitionTest {
    const PATH_PREFIX: &'static str;

    type Input: Serialize + DeserializeOwned + Debug + Clone;
    type JamInput;
    type State: Serialize + DeserializeOwned + Debug + Clone + PartialEq;
    type JamTransitionOutput;
    type Output: Serialize + DeserializeOwned + Debug + Clone + PartialEq;
    type ErrorCode;

    /// Loads a test case from the path to the test vectors.
    fn load_test_case(filename: &Path) -> TestCase<Self::Input, Self::Output, Self::State> {
        let path = PathBuf::from(Self::PATH_PREFIX).join(filename);
        let full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
        let json_str = fs::read_to_string(&full_path).expect("Failed to read test vector file");
        serde_json::from_str(&json_str).expect("Failed to parse JSON")
    }

    fn init_header_and_manager() -> (BlockHeader, StateManager) {
        let (_, _, manager, _) = fr_state::test_utils::init_db_and_manager(None);
        (BlockHeader::default(), manager)
    }

    async fn load_pre_state(
        test_pre_state: &Self::State,
        state_manager: Arc<StateManager>,
    ) -> Result<(), StateManagerError>;

    fn convert_input_type(test_input: &Self::Input) -> Result<Self::JamInput, TransitionError>;

    async fn run_state_transition(
        state_manager: Arc<StateManager>,
        new_header: &mut BlockHeader,
        jam_input: Self::JamInput,
    ) -> Result<Self::JamTransitionOutput, TransitionError>;

    fn map_error_code(e: TransitionError) -> Self::ErrorCode;

    fn extract_output(
        new_header: &BlockHeader,
        transition_output: Option<&Self::JamTransitionOutput>,
        error_code: &Option<Self::ErrorCode>,
    ) -> Self::Output;

    async fn extract_post_state(
        state_manager: Arc<StateManager>,
        pre_state: &Self::State,
        error_code: &Option<Self::ErrorCode>,
    ) -> Result<Self::State, StateManagerError>;

    fn assert_post_state(post_state: Self::State, test_case_post_state: Self::State) {
        assert_eq!(post_state, test_case_post_state)
    }
}

pub async fn run_test_case<T: StateTransitionTest>(filename: &str) -> Result<(), TransitionError> {
    // Config tracing subscriber
    setup_timed_tracing();

    // load test case
    let filename = PathBuf::from(filename);
    let test_case = T::load_test_case(&filename);

    // init state manager and header db
    let (mut new_header, state_manager) = T::init_header_and_manager();
    let state_manager = Arc::new(state_manager);

    // load pre-state to the cache and the DB
    T::load_pre_state(&test_case.pre_state, state_manager.clone()).await?;

    // commit the pre-state into the DB
    state_manager.commit_dirty_cache().await?;

    // clear state cache to ensure the test cases read state entries from the DB
    state_manager.clear_state_cache();

    // load JAM input types
    let jam_input = T::convert_input_type(&test_case.input)?;

    // run state transitions
    let transition_result =
        T::run_state_transition(state_manager.clone(), &mut new_header, jam_input).await;

    let (maybe_transition_output, maybe_error_code) = match transition_result {
        Ok(transition_output) => (Some(transition_output), None),
        Err(e) => (None, Some(T::map_error_code(e))),
    };

    // commit the post-state into the DB
    state_manager.commit_dirty_cache().await?;

    // clear state cache to ensure the test cases read state entries from the DB
    state_manager.clear_state_cache();

    // compare the actual and the expected post state
    let post_state =
        T::extract_post_state(state_manager, &test_case.pre_state, &maybe_error_code).await?;
    T::assert_post_state(post_state, test_case.post_state);

    // compare the output
    let output = T::extract_output(
        &new_header,
        maybe_transition_output.as_ref(),
        &maybe_error_code,
    );
    assert_eq!(output, test_case.output);

    Ok(())
}

/// Generates typed test functions from provided test cases.
///
/// # Usage
/// ```text
/// generate_typed_tests! {
///     TestType,
///     test_name1: "path/to/case1",
///     test_name2: "path/to/case2",
/// }
/// ```
///
/// The first entry represents type of the state transition test.
/// For the following entries, each entry generates a test function
/// that calls `run_test_case::<TestType>("path/to/case")`.
///
/// Ensure `run_test_case` is in scope and returns `Result<(), TransitionError>`.
#[macro_export]
macro_rules! generate_typed_tests {
    ($test_type:ty, $($name:ident: $path:expr,)*) => {
        $(
            #[tokio::test]
            async fn $name() -> Result<(), TransitionError> {
                run_test_case::<$test_type>($path).await
            }
        )*
    }
}
