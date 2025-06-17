mod test;
use dep::aztec::macros::aztec;

#[aztec]
pub contract RoshamboGame {
    use dep::aztec::{
        keys::getters::get_public_keys,
        macros::{functions::{initializer, internal, private, public, utility}, storage::storage},
    };
    use dep::aztec::prelude::{AztecAddress, Map, PublicImmutable, PublicMutable};
    use dep::aztec::protocol_types::traits::{Hash, ToField};

    #[storage]
    struct Storage<Context> {
        admin: PublicMutable<AztecAddress, Context>, // admin can end vote
        tally: Map<Field, PublicMutable<Field, Context>, Context>, // we will store candidate as key and number of votes as value
        vote_ended: PublicMutable<bool, Context>, // vote_ended is boolean
        active_at_block: PublicImmutable<u32, Context>, // when people can start voting
    }

    #[public]
    #[initializer]
    // annotation to mark function as a constructor
    fn constructor(admin: AztecAddress) {
        storage.admin.write(admin);
        storage.vote_ended.write(false);
        storage.active_at_block.initialize(context.block_number() as u32);
    }

    #[private]
    // annotation to mark function as private and expose private context
    fn cast_vote(candidate: Field) {
        let msg_sender_npk_m_hash = get_public_keys(context.msg_sender()).npk_m.hash();

        let secret = context.request_nsk_app(msg_sender_npk_m_hash); // get secret key of caller of function
        let nullifier = std::hash::pedersen_hash([context.msg_sender().to_field(), secret]); // derive nullifier from sender and secret
        context.push_nullifier(nullifier);
        RoshamboGame::at(context.this_address()).add_to_tally_public(candidate).enqueue(
            &mut context,
        );
    }

    #[public]
    #[internal]
    fn add_to_tally_public(candidate: Field) {
        assert(storage.vote_ended.read() == false, "Vote has ended"); // assert that vote has not ended
        let new_tally = storage.tally.at(candidate).read() + 1;
        storage.tally.at(candidate).write(new_tally);
    }

    #[public]
    fn end_vote() {
        assert(storage.admin.read().eq(context.msg_sender()), "Only admin can end votes"); // assert that caller is admin
        storage.vote_ended.write(true);
    }
    #[utility]
    unconstrained fn get_vote(candidate: Field) -> Field {
        storage.tally.at(candidate).read()
    }
}

/*
let alice_secret = std::hash::poseidon2::Poseidon2::hash([0], 1);
    let alice_mask = std::hash::poseidon2::Poseidon2::hash([1], 1);
    let bob_secret = std::hash::poseidon2::Poseidon2::hash([2], 1);
    let bob_mask = std::hash::poseidon2::Poseidon2::hash([3], 1);

    let round_state: RoundState<4, 2> = RoundState {
        round_number: 1,
        user_encrypt_secret_hashes: [
            poseidon2([alice_secret, -1], 2),
            poseidon2([bob_secret, -1], 2),
        ],
        user_mask_secret_hashes: [poseidon2([alice_mask, -1], 2), poseidon2([bob_mask, -1], 2)],
        previous_output_states: [UserOutputState::default(); 2],
    };

    let previous_round_hash = round_state.hash();
    let alice_state = [0, 1, 2, 3];
    let alice_reveal = [0, 1, 0, 1];
    let bob_state = [-1, -2, -3, -4];
    let bob_reveal = [1, 0, 1, 0];

    // after executing. we have ciphertexts and mask commitments, but no mask reveal commitments
    let alice_output = execute_round(
        alice_state,
        alice_reveal,
        alice_secret,
        alice_mask,
        round_state,
        previous_round_hash,
        0,
    );

    let round_state = round_state.update([alice_output.0, round_state.previous_output_states[1]]);
    let previous_round_hash = round_state.hash();

    let bob_output = execute_round(
        bob_state,
        bob_reveal,
        bob_secret,
        bob_mask,
        round_state,
        previous_round_hash,
        1,
    );

    let round_state = round_state.update([round_state.previous_output_states[0], bob_output.0]);
    let previous_round_hash = round_state.hash();

    let alice_output = execute_round(
        alice_state,
        alice_reveal,
        alice_secret,
        alice_mask,
        round_state,
        previous_round_hash,
        0,
    );

    let round_state = round_state.update([alice_output.0, round_state.previous_output_states[1]]);
    let previous_round_hash = round_state.hash();

    let bob_output = execute_round(
        bob_state,
        bob_reveal,
        bob_secret,
        bob_mask,
        round_state,
        previous_round_hash,
        1,
    );

    let alice_decrypted = alice_output.1[0];
    let bob_decrypted = bob_output.1[0];
*/
