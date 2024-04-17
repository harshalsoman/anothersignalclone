from protocols.x3dh import X3DH25519
from protocols.double_ratchet import DR25519

if __name__ == '__main__':
    bob = X3DH25519()
    alice = X3DH25519()

    (bob_id_pub, bob_spk_pub_enc, bob_spk_sig, bob_otpk_pub) = bob.init_x3dh_prep()

    msg = {
        'from': 'alice',
        'to': 'bob',
        'msg': 'hello'
    }

    (alice_sk, ad, cipher) = alice.init_x3dh(msg, bob_id_pub, bob_spk_pub_enc, bob_spk_sig, bob_otpk_pub)
    (bob_sk, msg) = bob.x3dh(ad, cipher)

    # double ratchet starts here
    # round 1
    alice_dr = DR25519(alice_sk)
    bob_dr = DR25519(bob_sk)

    bob_dr.update_ratchet(alice_dr.get_public_key())
    alice_dr.update_ratchet(bob_dr.get_public_key())
    alice_msg_key = alice_dr.update_ratchet_message()
    bob_msg_key = bob_dr.update_ratchet_message()
    print(alice_msg_key == bob_msg_key)

    alice_pk = alice_dr.change_key()
    bob_dr.update_ratchet(alice_pk)
    alice_msg_key = alice_dr.update_ratchet_message()
    bob_msg_key = bob_dr.update_ratchet_message()
    print(alice_msg_key == bob_msg_key)

    alice_msg_key = alice_dr.update_ratchet_message()
    bob_msg_key = bob_dr.update_ratchet_message()
    print(alice_msg_key == bob_msg_key)

    alice_msg_key = alice_dr.update_ratchet_message()
    bob_msg_key = bob_dr.update_ratchet_message()
    print(alice_msg_key == bob_msg_key)

    bob_pk = bob_dr.change_key()
    alice_dr.update_ratchet(bob_pk)
    alice_msg_key = alice_dr.update_ratchet_message()
    bob_msg_key = bob_dr.update_ratchet_message()
    print(alice_msg_key == bob_msg_key)



