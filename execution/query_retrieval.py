import hashlib
import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

record_files = {
    "Inventory A": "inventory_a_records.json",
    "Inventory B": "inventory_b_records.json",
    "Inventory C": "inventory_c_records.json",
    "Inventory D": "inventory_d_records.json",
}

inventory_param_files = {
    "Inventory A": "inventory_a_params.json",
    "Inventory B": "inventory_b_params.json",
    "Inventory C": "inventory_c_params.json",
    "Inventory D": "inventory_d_params.json",
}

pkg_file = "pkg_keys.json"
procurement_file = "procurement_officer_keys.json"


def load_json_file(file_name):
    """load a json file from the data folder."""
    file_path = DATA_DIR / file_name

    with open(file_path, "r", encoding="utf-8-sig") as file:
        return json.load(file)


def save_json_file(file_name, data):
    """save updated data back into the data folder."""
    file_path = DATA_DIR / file_name

    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)


def load_inventory_databases():
    databases = {}

    for node_name, file_name in record_files.items():
        databases[node_name] = load_json_file(file_name)

    return databases


def load_inventory_params():
    params = {}

    for node_name, file_name in inventory_param_files.items():
        params[node_name] = load_json_file(file_name)

    return params


def extended_gcd(a, b):
    """helper used for calculating the rsa private exponent."""
    if a == 0:
        return b, 0, 1

    gcd_value, x1, y1 = extended_gcd(b % a, a)

    x = y1 - (b // a) * x1
    y = x1

    return gcd_value, x, y


def mod_inverse(e, phi):
    """calculate d where e * d mod phi = 1."""
    gcd_value, x, _ = extended_gcd(e, phi)

    if gcd_value != 1:
        raise ValueError("modular inverse does not exist.")

    return x % phi


def generate_rsa_values(key_data):
    """derive rsa values from p, q, and e."""
    p = key_data["p"]
    q = key_data["q"]
    e = key_data["e"]

    n = p * q
    phi = (p - 1) * (q - 1)
    d = mod_inverse(e, phi)

    key_data["n"] = n
    key_data["phi"] = phi
    key_data["d"] = d

    return key_data


def initialise_parameters(pkg_keys, client_keys, inventory_params):
    """prepare rsa and harn parameters used in the retrieval workflow."""
    print("\n========== parameter initialisation ==========")

    generate_rsa_values(pkg_keys)
    generate_rsa_values(client_keys)

    save_json_file(pkg_file, pkg_keys)
    save_json_file(procurement_file, client_keys)

    print("\npkg key values")
    print(f"p = {pkg_keys['p']}")
    print(f"q = {pkg_keys['q']}")
    print(f"e = {pkg_keys['e']}")
    print(f"n = p * q = {pkg_keys['n']}")
    print(f"phi(n) = (p - 1) * (q - 1) = {pkg_keys['phi']}")
    print(f"d = e^-1 mod phi(n) = {pkg_keys['d']}")
    print(f"updated pkg file saved: data/{pkg_file}")

    print("\nquery client key values")
    print(f"p = {client_keys['p']}")
    print(f"q = {client_keys['q']}")
    print(f"e = {client_keys['e']}")
    print(f"n = p * q = {client_keys['n']}")
    print(f"phi(n) = (p - 1) * (q - 1) = {client_keys['phi']}")
    print(f"d = e^-1 mod phi(n) = {client_keys['d']}")
    print(f"updated client key file saved: data/{procurement_file}")

    print("\ninventory node harn parameters")
    for node_name, data in inventory_params.items():
        print(f"{node_name}: identity = {data['identity']}, random value = {data['random_value']}")


def find_item_quantity(database_data, item_id):
    """search one inventory database for a matching item id."""
    for record in database_data["records"]:
        if record["item_id"] == item_id:
            return record["quantity"]

    return None


def submit_query(inventory_databases):
    """submit an item query and check that all inventory nodes agree."""
    print("\n========== query submission ==========")

    item_id = input("authorised user, enter item id to search, example 002: ").strip()

    if item_id == "":
        item_id = "002"

    print(f"\nquery request: retrieve quantity for item {item_id}")

    results = {}

    for node_name, database_data in inventory_databases.items():
        quantity = find_item_quantity(database_data, item_id)
        results[node_name] = quantity
        print(f"{node_name} returned quantity: {quantity}")

    unique_results = set(results.values())

    if len(unique_results) == 1 and None not in unique_results:
        quantity = unique_results.pop()
        message = f"{item_id}|{quantity}"

        print("\nall inventory nodes returned the same result")
        print(f"query result message for approval: {message}")

        return message

    print("\nquery result is inconsistent or item was not found")
    print("query will not continue to multi-signature approval")

    return None


def multiply_mod(values, n):
    """multiply values together under modulo n."""
    result = 1

    for value in values:
        result = (result * value) % n

    return result


def hash_t_and_message(t_value, message):
    """create the h(t,m) value used in harn signing."""
    hash_input = str(t_value) + message
    hash_hex = hashlib.md5(hash_input.encode()).hexdigest()
    hash_decimal = int(hash_hex, 16)

    return hash_input, hash_hex, hash_decimal


def generate_secret_keys(pkg_keys, inventory_params):
    """generate one identity-based secret key for each inventory node."""
    print("\n========== harn secret key generation ==========")

    secret_keys = {}

    for node_name, data in inventory_params.items():
        identity = data["identity"]

        g_j = pow(identity, pkg_keys["d"], pkg_keys["n"])
        secret_keys[node_name] = g_j

        print(f"\n{node_name}")
        print("formula: g_j = id_j^d mod n")
        print(f"id_j = {identity}")
        print(f"g_j = {g_j}")

    return secret_keys


def generate_t_values(pkg_keys, inventory_params):
    """generate and aggregate the harn t values."""
    print("\n========== harn t value generation ==========")

    t_values = {}

    for node_name, data in inventory_params.items():
        random_value = data["random_value"]

        t_j = pow(random_value, pkg_keys["e"], pkg_keys["n"])
        t_values[node_name] = t_j

        print(f"\n{node_name}")
        print("formula: t_j = r_j^e mod n")
        print(f"r_j = {random_value}")
        print(f"t_j = {t_j}")

    aggregated_t = multiply_mod(t_values.values(), pkg_keys["n"])

    print("\naggregated t value")
    print("formula: t = product of all t_j mod n")
    print(f"t = {aggregated_t}")

    return t_values, aggregated_t


def generate_partial_signatures(pkg_keys, inventory_params, secret_keys, aggregated_t, message):
    """generate and aggregate each node's partial signature."""
    print("\n========== harn partial signature generation ==========")

    hash_input, hash_hex, hash_decimal = hash_t_and_message(aggregated_t, message)

    print(f"h(t,m) input = {hash_input}")
    print(f"h(t,m) md5 hex = {hash_hex}")
    print(f"h(t,m) decimal = {hash_decimal}")

    partial_signatures = {}

    for node_name, data in inventory_params.items():
        g_j = secret_keys[node_name]
        r_j = data["random_value"]

        s_j = (g_j * pow(r_j, hash_decimal, pkg_keys["n"])) % pkg_keys["n"]
        partial_signatures[node_name] = s_j

        print(f"\n{node_name}")
        print("formula: s_j = g_j * r_j^h(t,m) mod n")
        print(f"s_j = {s_j}")

    aggregated_s = multiply_mod(partial_signatures.values(), pkg_keys["n"])

    print("\naggregated multi-signature")
    print("formula: s = product of all s_j mod n")
    print(f"s = {aggregated_s}")

    return partial_signatures, aggregated_s


def get_identity_product(pkg_keys, inventory_params):
    """calculate product(ids) mod n for harn verification."""
    identities = []

    for node_data in inventory_params.values():
        identities.append(node_data["identity"])

    return multiply_mod(identities, pkg_keys["n"])


def verify_multi_signature(pkg_keys, inventory_params, aggregated_t, aggregated_s, message):
    """verify the final harn multi-signature."""
    print("\n========== multi-signature verification ==========")

    hash_input, hash_hex, hash_decimal = hash_t_and_message(aggregated_t, message)
    identity_product = get_identity_product(pkg_keys, inventory_params)

    left_side = pow(aggregated_s, pkg_keys["e"], pkg_keys["n"])
    right_side = (identity_product * pow(aggregated_t, hash_decimal, pkg_keys["n"])) % pkg_keys["n"]

    print("verification formula:")
    print("s^e mod n = product(ids) * t^h(t,m) mod n")
    print(f"h(t,m) input = {hash_input}")
    print(f"h(t,m) md5 hex = {hash_hex}")
    print(f"h(t,m) decimal = {hash_decimal}")

    print(f"\nleft side  = {left_side}")
    print(f"right side = {right_side}")

    is_valid = left_side == right_side

    print(f"multi-signature result: {'valid' if is_valid else 'invalid'}")

    return is_valid


def run_signature_consensus(pkg_keys, inventory_params, aggregated_t, aggregated_s, message):
    """let each inventory node verify the same aggregated signature."""
    print("\n========== multi-signature consensus check ==========")

    votes = {}

    for node_name in inventory_params:
        valid = verify_multi_signature(
            pkg_keys,
            inventory_params,
            aggregated_t,
            aggregated_s,
            message,
        )

        if valid:
            votes[node_name] = "ACCEPT"
        else:
            votes[node_name] = "REJECT"

        print(f"{node_name} vote: {votes[node_name]}")

    accept_count = list(votes.values()).count("ACCEPT")

    print("\nconsensus summary")
    for node_name, vote in votes.items():
        print(f"{node_name}: {vote}")

    print(f"total ACCEPT votes: {accept_count}")

    if accept_count == 4:
        print("multi-signature consensus result: ACCEPTED")
        return True

    print("multi-signature consensus result: REJECTED")
    return False


def text_to_integer(text):
    """convert text into an integer for rsa encryption."""
    return int.from_bytes(text.encode("utf-8"), byteorder="big")


def integer_to_text(number):
    """convert a decrypted integer back into readable text."""
    byte_length = (number.bit_length() + 7) // 8
    return number.to_bytes(byte_length, byteorder="big").decode("utf-8")


def encrypt_for_client(client_keys, response_text):
    """encrypt the approved response using the query client's public key."""
    print("\n========== secure response encryption ==========")

    message_integer = text_to_integer(response_text)

    if message_integer >= client_keys["n"]:
        raise ValueError("response message is too large for rsa encryption")

    ciphertext = pow(message_integer, client_keys["e"], client_keys["n"])

    print(f"plain approved response: {response_text}")
    print(f"response as integer: {message_integer}")
    print("encryption formula: c = m^e mod n")
    print(f"ciphertext = {ciphertext}")

    return ciphertext


def decrypt_by_client(client_keys, ciphertext):
    """decrypt the response using the query client's private key."""
    print("\n========== user side recovery ==========")

    recovered_integer = pow(ciphertext, client_keys["d"], client_keys["n"])
    recovered_text = integer_to_text(recovered_integer)

    print("decryption formula: m = c^d mod n")
    print(f"recovered integer = {recovered_integer}")
    print(f"recovered response = {recovered_text}")

    return recovered_text


def run_valid_query_workflow(pkg_keys, client_keys, inventory_params, inventory_databases):
    """run the full secure query workflow."""
    message = submit_query(inventory_databases)

    if message is None:
        return

    secret_keys = generate_secret_keys(pkg_keys, inventory_params)
    _, aggregated_t = generate_t_values(pkg_keys, inventory_params)

    _, aggregated_s = generate_partial_signatures(
        pkg_keys,
        inventory_params,
        secret_keys,
        aggregated_t,
        message,
    )

    valid_signature = verify_multi_signature(
        pkg_keys,
        inventory_params,
        aggregated_t,
        aggregated_s,
        message,
    )

    if not valid_signature:
        print("multi-signature failed, response will not be sent")
        return

    consensus_ok = run_signature_consensus(
        pkg_keys,
        inventory_params,
        aggregated_t,
        aggregated_s,
        message,
    )

    if not consensus_ok:
        print("inventory nodes did not agree on the multi-signature")
        return

    approved_response = message + "|OK"

    ciphertext = encrypt_for_client(client_keys, approved_response)
    recovered_response = decrypt_by_client(client_keys, ciphertext)

    print("\n========== final recovery check ==========")
    print(f"approved response = {approved_response}")
    print(f"recovered response = {recovered_response}")

    if approved_response == recovered_response:
        print("recovery result: SUCCESS")
    else:
        print("recovery result: FAILED")


def run_tampered_result_test(pkg_keys, inventory_params):
    """show that changing an approved query result breaks verification."""
    print("\n========== tampered query result test ==========")

    original_message = input("enter original approved result, example 002|20: ").strip()
    tampered_message = input("enter tampered result, example 002|21: ").strip()

    if original_message == "":
        original_message = "002|20"

    if tampered_message == "":
        tampered_message = "002|21"

    print(f"\noriginal approved result = {original_message}")
    print(f"tampered result = {tampered_message}")

    secret_keys = generate_secret_keys(pkg_keys, inventory_params)
    _, aggregated_t = generate_t_values(pkg_keys, inventory_params)

    _, aggregated_s = generate_partial_signatures(
        pkg_keys,
        inventory_params,
        secret_keys,
        aggregated_t,
        original_message,
    )

    print("\nchecking the same signature against the tampered result")

    verify_multi_signature(
        pkg_keys,
        inventory_params,
        aggregated_t,
        aggregated_s,
        tampered_message,
    )


def main():
    print("secure distributed inventory system")
    print("multi-signature query verification and secure response delivery")

    inventory_databases = load_inventory_databases()
    inventory_params = load_inventory_params()
    pkg_keys = load_json_file(pkg_file)
    client_keys = load_json_file(procurement_file)

    initialise_parameters(pkg_keys, client_keys, inventory_params)

    while True:
        print("\n==============================================")
        print("secure distributed inventory system")
        print("secure query retrieval")
        print("==============================================")
        print("1. submit query and run secure retrieval workflow")
        print("2. demonstrate tampered query result rejection")
        print("3. exit")

        choice = input("\nselect an option: ").strip()

        if choice == "1":
            run_valid_query_workflow(
                pkg_keys,
                client_keys,
                inventory_params,
                inventory_databases,
            )

        elif choice == "2":
            run_tampered_result_test(pkg_keys, inventory_params)

        elif choice == "3":
            print("\nexiting secure query retrieval system.")
            break

        else:
            print("\ninvalid option, choose 1, 2, or 3")


if __name__ == "__main__":
    main()