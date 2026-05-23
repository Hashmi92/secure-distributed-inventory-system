import hashlib
import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

key_files = {
    "Inventory A": "inventory_a_keys.json",
    "Inventory B": "inventory_b_keys.json",
    "Inventory C": "inventory_c_keys.json",
    "Inventory D": "inventory_d_keys.json",
}

record_files = {
    "Inventory A": "inventory_a_records.json",
    "Inventory B": "inventory_b_records.json",
    "Inventory C": "inventory_c_records.json",
    "Inventory D": "inventory_d_records.json",
}


def load_json_file(file_name):
    """load a json file from the data folder."""
    file_path = DATA_DIR / file_name

    try:
        with open(file_path, "r", encoding="utf-8-sig") as file:
            content = file.read().strip()

        if content == "":
            raise ValueError("file is empty")

        return json.loads(content)

    except Exception as error:
        print("\n========== json file error ==========")
        print(f"problem file: {file_path}")
        print(f"error: {error}")

        if file_path.exists():
            with open(file_path, "r", encoding="utf-8-sig") as file:
                preview = file.read()[:300]

            print("\nfile content preview:")
            print(repr(preview))

        raise


def save_json_file(file_name, data):
    """save updated data back into the data folder."""
    file_path = DATA_DIR / file_name

    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)


def load_inventory_keys():
    keys = {}

    for node_name, file_name in key_files.items():
        keys[node_name] = load_json_file(file_name)

    return keys


def load_inventory_databases():
    databases = {}

    for node_name, file_name in record_files.items():
        databases[node_name] = load_json_file(file_name)

    return databases


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
        raise ValueError("modular inverse does not exist because e and phi are not coprime.")

    return x % phi


def record_to_message(record):
    """convert a record into a consistent message before hashing."""
    return record["item_id"] + record["quantity"] + record["price"] + record["location"]


def md5_to_decimal(message):
    """create an md5 digest and convert it into an integer for rsa."""
    md5_hex = hashlib.md5(message.encode()).hexdigest()
    md5_decimal = int(md5_hex, 16)

    return md5_hex, md5_decimal


def generate_rsa_values(inventory_keys):
    """derive rsa values from p, q, and e for each inventory node."""
    print("\n========== rsa parameter setup ==========")

    for node_name, key_data in inventory_keys.items():
        p = key_data["p"]
        q = key_data["q"]
        e = key_data["e"]

        n = p * q
        phi = (p - 1) * (q - 1)
        d = mod_inverse(e, phi)

        key_data["n"] = n
        key_data["phi"] = phi
        key_data["d"] = d

        print(f"\n{node_name} rsa values generated:")
        print(f"p = {p}")
        print(f"q = {q}")
        print(f"e = {e}")
        print(f"n = p * q = {n}")
        print(f"phi(n) = (p - 1) * (q - 1) = {phi}")
        print(f"d = e^-1 mod phi(n) = {d}")

        save_json_file(key_files[node_name], key_data)
        print(f"updated key file saved: data/{key_files[node_name]}")


def get_record_from_user():
    print("\n========== new inventory record ==========")

    item_id = input("enter item id, example 008: ").strip()
    quantity = input("enter quantity, example 20: ").strip()
    price = input("enter price, example 45: ").strip()
    location = input("enter location, example D: ").strip().upper()

    record = {
        "item_id": item_id,
        "quantity": quantity,
        "price": price,
        "location": location,
    }

    print(f"\nrecord entered: {item_id},{quantity},{price},{location}")
    print(f"message used for hashing: {record_to_message(record)}")

    return record


def get_sender_from_user():
    print("\nchoose the inventory node signing the record:")
    print("1. Inventory A")
    print("2. Inventory B")
    print("3. Inventory C")
    print("4. Inventory D")

    choice = input("select signer node: ").strip()

    if choice == "1":
        return "Inventory A"
    if choice == "2":
        return "Inventory B"
    if choice == "3":
        return "Inventory C"
    if choice == "4":
        return "Inventory D"

    print("invalid choice, using Inventory A as default.")
    return "Inventory A"


def sign_record(record, sender_node, inventory_keys):
    """sign the record hash using the sender's rsa private key."""
    message = record_to_message(record)
    md5_hex, md5_decimal = md5_to_decimal(message)

    sender_d = inventory_keys[sender_node]["d"]
    sender_n = inventory_keys[sender_node]["n"]

    signature = pow(md5_decimal, sender_d, sender_n)

    print("\n========== signing process ==========")
    print(f"originating node: {sender_node}")
    print(f"record being signed: {record['item_id']},{record['quantity']},{record['price']},{record['location']}")
    print(f"message used for signing: {message}")
    print(f"md5 hash in hex: {md5_hex}")
    print(f"md5 hash in decimal: {md5_decimal}")
    print("rsa signing formula: signature = m^d mod n")
    print(f"generated signature: {signature}")

    return {
        "record": record,
        "message": message,
        "hash_hex": md5_hex,
        "hash_decimal": md5_decimal,
        "signature": signature,
        "sender": sender_node,
    }


def verify_record(signed_package, verifier_node, inventory_keys):
    """verify a signed record using the sender's rsa public key."""
    record = signed_package["record"]
    sender_node = signed_package["sender"]
    signature = signed_package["signature"]

    message = record_to_message(record)
    recomputed_hash_hex, recomputed_hash_decimal = md5_to_decimal(message)

    sender_e = inventory_keys[sender_node]["e"]
    sender_n = inventory_keys[sender_node]["n"]

    recovered_hash_decimal = pow(signature, sender_e, sender_n)
    is_valid = recovered_hash_decimal == recomputed_hash_decimal

    print("\n========== verification process ==========")
    print(f"verifier node: {verifier_node}")
    print(f"claimed sender: {sender_node}")
    print(f"public key used: e and n of {sender_node}")
    print(f"received message: {message}")
    print(f"recomputed md5 hash in hex: {recomputed_hash_hex}")
    print(f"recomputed md5 hash in decimal: {recomputed_hash_decimal}")
    print(f"recovered hash from signature: {recovered_hash_decimal}")
    print(f"verification result: {'valid' if is_valid else 'invalid'}")

    return is_valid


def validate_record_format(record):
    required_fields = ["item_id", "quantity", "price", "location"]

    for field in required_fields:
        if field not in record or record[field] == "":
            return False

    if not record["item_id"].isdigit():
        return False

    if not record["quantity"].isdigit():
        return False

    if not record["price"].isdigit():
        return False

    if len(record["location"]) != 1 or not record["location"].isalpha():
        return False

    return True


def record_exists(database_data, record):
    for existing_record in database_data["records"]:
        if existing_record == record:
            return True

    return False


def validator_vote(signed_package, validator_node, inventory_keys, inventory_databases):
    """run validation checks before a node votes on the record."""
    record = signed_package["record"]

    print(f"\n----- {validator_node} validator check -----")

    format_valid = validate_record_format(record)
    signature_valid = verify_record(signed_package, validator_node, inventory_keys)
    duplicate_record = record_exists(inventory_databases[validator_node], record)

    print(f"record format valid: {format_valid}")
    print(f"signature valid: {signature_valid}")
    print(f"duplicate record already in {validator_node} file: {duplicate_record}")

    if format_valid and signature_valid and not duplicate_record:
        print(f"{validator_node} vote: ACCEPT")
        return "ACCEPT"

    print(f"{validator_node} vote: REJECT")
    return "REJECT"


def run_authority_consensus(signed_package, inventory_keys, inventory_databases):
    """run proof-of-authority voting across the known inventory nodes."""
    print("\n========== proof-of-authority consensus ==========")
    print("validators: Inventory A, Inventory B, Inventory C, Inventory D")
    print("decision rule: at least 3 out of 4 validators must vote ACCEPT")

    validators = ["Inventory A", "Inventory B", "Inventory C", "Inventory D"]
    votes = {}

    for validator in validators:
        votes[validator] = validator_vote(
            signed_package,
            validator,
            inventory_keys,
            inventory_databases,
        )

    accept_count = list(votes.values()).count("ACCEPT")
    reject_count = list(votes.values()).count("REJECT")

    print("\n========== consensus vote summary ==========")

    for node_name, vote in votes.items():
        print(f"{node_name}: {vote}")

    print(f"total ACCEPT votes: {accept_count}")
    print(f"total REJECT votes: {reject_count}")

    consensus_accepted = accept_count >= 3

    if consensus_accepted:
        print("final consensus decision: ACCEPTED")
        store_record_in_all_nodes(signed_package["record"], inventory_databases)
    else:
        print("final consensus decision: REJECTED")
        print("record will not be stored in local record files.")

    return consensus_accepted, votes


def store_record_in_all_nodes(record, inventory_databases):
    """store the accepted record in every local inventory file."""
    print("\n========== storing accepted record ==========")

    for node_name, database_data in inventory_databases.items():
        database_data["records"].append(record)
        save_json_file(record_files[node_name], database_data)

        print(f"{node_name}: record stored in data/{record_files[node_name]}")


def show_local_databases(inventory_databases):
    print("\n========== local inventory records ==========")

    for node_name, database_data in inventory_databases.items():
        print(f"\n{node_name} records from file:")

        for record in database_data["records"]:
            print(f"{record['item_id']},{record['quantity']},{record['price']},{record['location']}")


def run_valid_record_lifecycle(inventory_keys, inventory_databases):
    record = get_record_from_user()
    sender_node = get_sender_from_user()

    print("\n========== record creation ==========")
    print(f"{sender_node} creates a new inventory update.")
    print(f"new record: {record['item_id']},{record['quantity']},{record['price']},{record['location']}")

    signed_package = sign_record(record, sender_node, inventory_keys)

    print("\n========== broadcasting signed record ==========")
    print(f"{sender_node} broadcasts the signed record to the validators.")

    run_authority_consensus(signed_package, inventory_keys, inventory_databases)


def run_tampered_record_lifecycle(inventory_keys, inventory_databases):
    """sign a record first, then change it to show tamper detection."""
    original_record = get_record_from_user()
    sender_node = get_sender_from_user()

    print("\n========== tampered record demonstration ==========")
    print(f"step 1: {sender_node} signs the original record.")
    print(f"original record: {original_record['item_id']},{original_record['quantity']},{original_record['price']},{original_record['location']}")

    signed_package = sign_record(original_record, sender_node, inventory_keys)

    print("\nstep 2: change the quantity after signing")
    new_quantity = input("enter tampered quantity, example 21: ").strip()

    tampered_record = original_record.copy()
    tampered_record["quantity"] = new_quantity

    print(f"tampered record: {tampered_record['item_id']},{tampered_record['quantity']},{tampered_record['price']},{tampered_record['location']}")

    signed_package["record"] = tampered_record

    print("\nstep 3: validators check the modified package.")

    run_authority_consensus(signed_package, inventory_keys, inventory_databases)


def main():
    print("secure distributed inventory system")
    print("record authentication and consensus-based insertion")

    inventory_keys = load_inventory_keys()
    inventory_databases = load_inventory_databases()

    generate_rsa_values(inventory_keys)

    while True:
        print("\n==============================================")
        print("secure distributed inventory system")
        print("==============================================")
        print("1. sign a new record and run consensus")
        print("2. sign a record, modify it, and show rejection")
        print("3. show local inventory records")
        print("4. exit")

        choice = input("\nselect an option: ").strip()

        if choice == "1":
            run_valid_record_lifecycle(inventory_keys, inventory_databases)

        elif choice == "2":
            run_tampered_record_lifecycle(inventory_keys, inventory_databases)

        elif choice == "3":
            show_local_databases(inventory_databases)

        elif choice == "4":
            print("\nexiting secure record insertion system.")
            break

        else:
            print("\ninvalid option. please choose 1, 2, 3, or 4.")


if __name__ == "__main__":
    main()