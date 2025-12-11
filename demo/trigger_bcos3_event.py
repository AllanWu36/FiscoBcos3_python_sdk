
import time
import sys
sys.path.append("./")
from bcos3sdk.bcos3client import Bcos3Client
from client.contractnote import ContractNote
from client.datatype_parser import DatatypeParser

# Initialize Client
client = Bcos3Client()
print(client.getinfo())

# Get Contract Address
contract_name = "HelloWorld"
address = ContractNote.get_last(client.get_full_name(), contract_name)
print(f"Contract Address: {address}")

if not address:
    print("Contract not found, please deploy it first.")
    sys.exit(1)

# Load ABI
abi_file = f"contracts/{contract_name}.abi"
parser = DatatypeParser(abi_file)
contract_abi = parser.contract_abi

# Send Transaction to trigger event
new_name = f"Hello Fisco {time.strftime('%Y-%m-%d %H:%M:%S')}"
print(f"Sending transaction to call 'set' with value: '{new_name}'...")

receipt = client.sendRawTransaction(
    to_address=address,
    contract_abi=contract_abi,
    fn_name="set",
    args=[new_name]
)

print("Transaction receipt:")
if "status" in receipt:
    print(f"Status: {receipt['status']}")
if "transactionHash" in receipt:
    print(f"TxHash: {receipt['transactionHash']}")
print("Done. Event 'onset' should be emitted.")
