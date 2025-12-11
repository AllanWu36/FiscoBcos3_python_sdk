import json
import os
import sys
import time
sys.path.append("./")
from ctypes import byref

from bcos3sdk.bcos3callbackfuture import BcosCallbackFuture
from bcos3sdk.bcos3datadef import s2b

from bcos3sdk.bcos3sdk_wrap import *
from client.common.common import print_receipt_logs

from bcos3sdk.bcos3client import Bcos3Client
from client.datatype_parser import DatatypeParser

bcos3client = Bcos3Client()
print(bcos3client.getinfo())
num = bcos3client.getBlockNumber()
print(f"Current block number {num}")

from client.contractnote import ContractNote

current_address = ContractNote.get_last(bcos3client.get_full_name(), "HelloWorld")
print("Current address:", current_address)

(currpath, currfile) = os.path.split(os.path.realpath(__file__))

# https://fisco-bcos-doc.readthedocs.io/zh_CN/latest/docs/develop/sdk/java_sdk/event_sub.html
eventName = "onset"
fromBlock = -1
toBlock = -1
parser = DatatypeParser("contracts/HelloWorld.abi")

testtype = 0

# bcos3client封装测试
if testtype == 0:
    (subid, cbfuture) = bcos3client.event_subscribe(
        current_address,
        eventName,
        parser.contract_abi,
        fromBlock=fromBlock, toBlock=toBlock)

# ctypes 封装测试
if testtype == 1:
    cbfuture = BcosCallbackFuture(currfile, "")
    
    event_param = dict()
    event_param["fromBlock"] = fromBlock  # change this for new event
    event_param["toBlock"] = toBlock  # change this for new event
    event_param["addresses"] = [current_address]  # sample helloWorld address
    event_param["topics"] = []
    
    event_name = eventName
    eventtopic = parser.topic_from_event_name(event_name)
    event_param["topics"].append(eventtopic)
    eventparam_json = json.dumps(event_param)
    print("Subcribe event ,input param in str: ", eventparam_json)
    subid = bcos3client.bcossdk.bcos_event_sub_subscribe_event(bcos3client.bcossdk.sdk,
                                                               s2b(bcos3client.group),
                                                               s2b(eventparam_json),
                                                               cbfuture.callback,
                                                               byref(cbfuture.context))

print("-----START: ", cbfuture.context.detail())
print("->EventSub result: ", subid)
print("callback:")
cbfuture.display()

waittick = 0
lasttick = time.time()
while True:
    (is_timeout, resp) = cbfuture.wait()
    if is_timeout is False:  # default timeout 5 sec
        print(">>> CBFuture Get Message")
        print(f"{resp.data.strip()}")
        try:
            result = bcos3client.get_result(resp.data)
            logs = parser.parse_event_logs(result)
            print_receipt_logs(logs)
        except Exception as e:
            print(f"Skip parse event log: {e}")
    else:
        print(f">>> CBFuture {subid} timeout ,try again")
    
    nowtick = time.time()
    if nowtick - lasttick > 3:
        waittick = waittick + 1
        print(f"WaitTick : {waittick}")
        lasttick = time.time()
    
    if waittick >= 50:
        break

bcos3client.bcossdk.bcos_event_sub_unsubscribe_event(bcos3client.bcossdk.sdk, subid)
bcos3client.finish()
print("Event listen test done")
