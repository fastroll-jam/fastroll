use rjam_db::BlockHeaderDB;
use rjam_state::StateManager;
use rjam_transition::error::TransitionError;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    fmt::Debug,
    fs,
    path::{Path, PathBuf},
};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TestCase<I, O, S> {
    pub input: I,
    pub pre_state: S,
    pub output: O,
    pub post_state: S,
}

pub trait StateTransitionTest {
    const PATH_PREFIX: &'static str;

    type Input: Serialize + DeserializeOwned + Debug + Clone;
    type JamInput;
    type State: Serialize + DeserializeOwned + Debug + Clone + PartialEq;
    type Output: Serialize + DeserializeOwned + Debug + Clone + PartialEq;
    type ErrorCode;

    /// Loads a test case from the path to the test vectors.
    fn load_test_case(filename: &Path) -> TestCase<Self::Input, Self::Output, Self::State> {
        let path = PathBuf::from(Self::PATH_PREFIX).join(filename);
        let full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
        let json_str = fs::read_to_string(&full_path).expect("Failed to read test vector file");
        let test_case = serde_json::from_str(&json_str).expect("Failed to parse JSON");
        test_case
    }

    fn setup_state_manager(test_pre_state: &Self::State) -> Result<StateManager, TransitionError>;

    fn setup_header_db() -> BlockHeaderDB {
        BlockHeaderDB::initialize_for_test()
    }

    fn convert_input_type(test_input: &Self::Input) -> Result<Self::JamInput, TransitionError>;

    fn run_state_transition(
        state_manager: &StateManager,
        header_db: &mut BlockHeaderDB,
        jam_input: &Self::JamInput,
    ) -> Result<(), TransitionError>;

    fn map_error_code(e: TransitionError) -> Self::ErrorCode;

    fn extract_output(
        header_db: &BlockHeaderDB,
        error_code: &Option<Self::ErrorCode>,
    ) -> Self::Output;

    fn extract_post_state(
        state_manager: &StateManager,
        pre_state: &Self::State,
        error_code: &Option<Self::ErrorCode>,
    ) -> Self::State;
}

pub fn run_test_case<T: StateTransitionTest>(filename: &str) -> Result<(), TransitionError> {
    // load test case
    let filename = PathBuf::from(filename);
    let test_case = T::load_test_case(&filename);

    // setup state manager and load current state
    let state_manager = T::setup_state_manager(&test_case.pre_state)?;

    // setup header db
    let mut header_db = T::setup_header_db();

    // load JAM input types
    let jam_input = T::convert_input_type(&test_case.input)?;

    // run state transitions
    let result = T::run_state_transition(&state_manager, &mut header_db, &jam_input);

    let maybe_error_code = result.err().map(T::map_error_code);

    // compare the actual and the expected post state
    let post_state = T::extract_post_state(&state_manager, &test_case.pre_state, &maybe_error_code); // TODO: dliver may_eror_code too
    assert_eq!(post_state, test_case.post_state);

    // compare the output
    let output = T::extract_output(&header_db, &maybe_error_code);
    assert_eq!(output, test_case.output);

    Ok(())
}
