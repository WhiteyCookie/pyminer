#!/usr/bin/python3
import time
import json
import pprint
import hashlib
import struct
import re
import base64
import http.client
import sys
from multiprocessing import Process

ERR_SLEEP = 15
MAX_NONCE = 1000000

settings = {}
pp = pprint.PrettyPrinter(indent=4)

class BitcoinRPC:
    OBJID = 1

    def __init__(self, host, port, username, password):
        authpair = f"{username}:{password}"
        self.authhdr = "Basic {}".format(base64.b64encode(authpair.encode()).decode())
        self.host = host
        self.port = port
        self.conn = None

    def rpc(self, method, params=None, retries=3):
        self.OBJID += 1
        obj = {
            'version': '1.1',
            'method': method,
            'id': self.OBJID
        }
        if params is None:
            obj['params'] = []
        else:
            obj['params'] = params

        #print(f"Sending RPC request to {self.host}:{self.port}, method: {method}, params: {params}")

        for attempt in range(retries):
            try:
                # Close and reopen the connection for each request
                if self.conn:
                    self.conn.close()
                self.conn = http.client.HTTPConnection(self.host, self.port, timeout=30)
                
                self.conn.request(
                    'POST', '/', json.dumps(obj),
                    {
                        'Authorization': self.authhdr,
                        'Content-type': 'application/json'
                    }
                )

                resp = self.conn.getresponse()
                if resp is None:
                    print("JSON-RPC: no response")
                    return None

                #print(f"RPC Response status: {resp.status} {resp.reason}")
                
                if resp.status != 200:
                    print(f"JSON-RPC: HTTP error {resp.status} {resp.reason}")
                    return None

                body = resp.read().decode()
                if not body:
                    print("JSON-RPC: Empty response body")
                    return None

                try:
                    resp_obj = json.loads(body)
                    #print(f"RPC Response: {resp_obj}")
                except json.JSONDecodeError as e:
                    print(f"JSON-RPC: Error decoding JSON - {str(e)}")
                    return None

                if 'error' in resp_obj and resp_obj['error'] is not None:
                    print(f"RPC Error: {resp_obj['error']}")
                    return resp_obj['error']
                if 'result' not in resp_obj:
                    print("JSON-RPC: no result in object")
                    return None

                return resp_obj['result']

            except (TimeoutError, http.client.HTTPException) as e:
                print(f"RPC request failed with error: {str(e)}")
                if attempt < retries - 1:
                    print(f"Retrying... ({attempt + 1}/{retries})")
                    time.sleep(2)  # Small delay before retrying
                else:
                    print("Max retries reached, giving up.")
                    return None


    def getblocktemplate(self, capabilities=None):
        if capabilities is None:
            capabilities = [{"rules": ["segwit"], "capabilities": ["proposal"]}]
        return self.rpc('getblocktemplate', capabilities)


def uint32(x):
    return x & 0xffffffff


def bytereverse(x):
    return uint32(((x << 24) | ((x << 8) & 0x00ff0000) |
                   ((x >> 8) & 0x0000ff00) | (x >> 24)))


def bufreverse(in_buf):
    out_words = []
    for i in range(0, len(in_buf), 4):
        word = struct.unpack('@I', in_buf[i:i+4])[0]
        out_words.append(struct.pack('@I', bytereverse(word)))
    return b''.join(out_words)


def wordreverse(in_buf):
    out_words = []
    for i in range(0, len(in_buf), 4):
        out_words.append(in_buf[i:i+4])
    out_words.reverse()
    return b''.join(out_words)


class Miner:
    def __init__(self, id):
        self.id = id
        self.max_nonce = MAX_NONCE
        print(f"Miner {self.id} initialized with max_nonce: {self.max_nonce}")

    def work(self, blockheader, targetstr):
        print(f"Miner {self.id} starting work with blockheader: {blockheader} and target: {targetstr}")
        
        static_data = bytes.fromhex(blockheader)
        static_data = bufreverse(static_data)

        blk_hdr = static_data[:76]

        targetbin = bytes.fromhex(targetstr)
        targetbin = targetbin[::-1]  
        targetbin_str = targetbin.hex()
        target = int(targetbin_str, 16)

        static_hash = hashlib.sha256()
        static_hash.update(blk_hdr)

        for nonce in range(self.max_nonce):
            nonce_bin = struct.pack("<I", nonce)

            hash1_o = static_hash.copy()
            hash1_o.update(nonce_bin)
            hash1 = hash1_o.digest()

            hash_o = hashlib.sha256()
            hash_o.update(hash1)
            hash_final = hash_o.digest()

            if hash_final[-4:] != b'\0\0\0\0':
                continue

            hash_final = bufreverse(hash_final)
            hash_final = wordreverse(hash_final)

            hash_str = hash_final.hex()
            l = int(hash_str, 16)

            if l < target:
                print(time.asctime(), f"Miner {self.id}: PROOF-OF-WORK found: {l:064x}")
                return (nonce + 1, nonce_bin)
            else:
                print(time.asctime(), f"Miner {self.id}: False positive: {l:064x}")

        print(f"Miner {self.id} completed work, no valid proof found.")
        return (nonce + 1, None)

    def submit_work(self, rpc, blockheader, nonce_bin):
        nonce_bin = bufreverse(nonce_bin)
        nonce = nonce_bin.hex()
        solution = blockheader[:152] + nonce + blockheader[160:256]
        param_arr = [solution]
        print(f"Miner {self.id} submitting work: {solution}")
        result = rpc.getblocktemplate(param_arr)
        print(time.asctime(), f"Miner {self.id} --> Upstream RPC result: {result}")

    def iterate(self, rpc):
        print(f"Miner {self.id} requesting work...")
        work = rpc.getblocktemplate()
        if work is None:
            print(f"Miner {self.id} no work received, sleeping for {ERR_SLEEP} seconds.")
            time.sleep(ERR_SLEEP)
            return
        if 'previousblockhash' not in work or 'target' not in work:
            print(f"Miner {self.id} received invalid work, sleeping for {ERR_SLEEP} seconds.")
            time.sleep(ERR_SLEEP)
            return

        time_start = time.time()

        (hashes_done, nonce_bin) = self.work(work['previousblockhash'], work['target'])

        time_end = time.time()
        time_diff = time_end - time_start

        self.max_nonce = int(
            (hashes_done * settings['scantime']) / time_diff)
        if self.max_nonce > 0xfffffffa:
            self.max_nonce = 0xfffffffa

        print(f"Miner {self.id} completed a cycle. Hashes done: {hashes_done}, Time taken: {time_diff:.2f} seconds")

        if settings['hashmeter']:
            print(f"HashMeter({self.id}): {hashes_done} hashes, {(hashes_done / 1000.0) / time_diff:.2f} Khash/sec")

        if nonce_bin is not None:
            self.submit_work(rpc, work['previousblockhash'], nonce_bin)

    def loop(self):
        rpc = BitcoinRPC(settings['host'], settings['port'],
                         settings['rpcuser'], settings['rpcpass'])
        if rpc is None:
            print(f"Miner {self.id}: Failed to create RPC connection.")
            return

        while True:
            self.iterate(rpc)


def miner_thread(id):
    miner = Miner(id)
    miner.loop()


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: pyminer.py CONFIG-FILE")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        for line in f:
            if re.search(r'^\s*#', line):
                continue

            m = re.search(r'^(\w+)\s*=\s*(\S.*)$', line)
            if m is None:
                continue
            settings[m.group(1)] = m.group(2)

    if 'host' not in settings:
        settings['host'] = '192.168.2.161'
    if 'port' not in settings:
        settings['port'] = 8332
    if 'threads' not in settings:
        settings['threads'] = 1
    if 'hashmeter' not in settings:
        settings['hashmeter'] = 0
    if 'scantime' not in settings:
        settings['scantime'] = 30
    if 'rpcuser' not in settings or 'rpcpass' not in settings:
        print("Missing username and/or password in cfg file")
        sys.exit(1)

    settings['port'] = int(settings['port'])
    settings['threads'] = int(settings['threads'])
    settings['hashmeter'] = int(settings['hashmeter'])
    settings['scantime'] = int(settings['scantime'])

    thr_list = []
    for thr_id in range(settings['threads']):
        p = Process(target=miner_thread, args=(thr_id,))
        p.start()
        thr_list.append(p)
        time.sleep(1)  # stagger threads

    print(f"{settings['threads']} mining thread{'s' if settings['threads'] > 1 else ''} started")

    print(time.asctime(), "Miner Starts - %s:%s" % (settings['host'], settings['port']))
    try:
        for thr_proc in thr_list:
            thr_proc.join()
    except KeyboardInterrupt:
        pass
    print(time.asctime(), "Miner Stops - %s:%s" % (settings['host'], settings['port']))
