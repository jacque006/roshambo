use dep::aztec::{prelude::AztecAddress, test::helpers::test_environment::TestEnvironment};

use crate::RoshamboGame;

pub unconstrained fn setup() -> (&mut TestEnvironment, AztecAddress, AztecAddress) {
    let mut env = TestEnvironment::new();

    let admin = env.create_account(1);

    let initializer_call_interface = RoshamboGame::interface().constructor(admin);
    let voting_contract = env.deploy_self("RoshamboGame").with_public_void_initializer(
        admin,
        initializer_call_interface,
    );

    env.advance_block_by(1);
    (&mut env, voting_contract.to_address(), admin)
}
