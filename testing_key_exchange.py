from key_exchange_master import KeyExchangeMain
from key_exchange_slave import KeyExchangeEdge

edge = KeyExchangeEdge()
main = KeyExchangeMain(1)

# edge stage one
stage_one_msg_edge = edge.stage_one()
# main stage one
stage_one_msg_main, signature_one_main = main.stage_one(stage_one_msg_edge)
# edge stage two
public_key_edge_dh = edge.stage_two(stage_one_msg_main, signature_one_main)
# main stage two
public_key_main_dh, shared_key_main = main.stage_two(public_key_edge_dh)
# edge stage three
ack, signature_three_edge, shared_key_edge = edge.stage_three(public_key_main_dh)
# main stage three
print("Last signature check worked? --> {}".format(main.stage_three(ack, signature_three_edge)))
print("Shared-key is equal on both sides? --> {}".format(shared_key_edge == shared_key_main))