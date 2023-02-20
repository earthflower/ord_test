import test from "ava";
import { toXOnly } from "bitcoinjs-lib/src/psbt/bip371";
import * as bitcoin from "bitcoinjs-lib";
import ecc from "@bitcoinerlab/secp256k1";
import * as Bitcoin from "bitcoinjs-lib";
import rng from "randombytes";
import BIP32Factory from "bip32";

const bip32 = BIP32Factory(ecc);

const PROTOCOL_ID = Buffer.from("ord");
const BODY_TAG = bitcoin.opcodes.OP_1;
const CONTENT_TYPE_TAG = Buffer.from([1]);
const ANNEX_PREFIX = 0x50;
const TAPROOT_WITNESS_VERSION = 0x01;
const TAPROOT_ANNEX_PREFIX = 0x50;
const SCHNORR_SIGNATURE_SIZE = 64;
const LEAF_VERSION_TAPSCRIPT = 0xc0; //TAPROOT_LEAF_TAPSCRIPT

export interface Inscription {
  body: Buffer;
  content_type: string;
}
export const appendRevealScript = (inscription: Inscription) => {
  function makeChunks(buffer, chunkSize = 520) {
    const chunks = [];
    for (let i = 0; i < buffer.length; i += chunkSize) {
      //@ts-ignore
      chunks.push(buffer.slice(i, i + chunkSize));
    }
    return chunks;
  }
  let instructions = [
    bitcoin.opcodes.OP_FALSE,
    bitcoin.opcodes.OP_IF,
    PROTOCOL_ID,
  ];
  if (inscription.content_type) {
    instructions.push(CONTENT_TYPE_TAG);
    instructions.push(Buffer.from(inscription.content_type));
  }
  if (inscription.body) {
    instructions.push(BODY_TAG);
    const chunks = makeChunks(Buffer.from(inscription.body), 520);
    for (let chunk of chunks) {
      instructions.push(Buffer.from(chunk));
    }
  }
  instructions.push(bitcoin.opcodes.OP_ENDIF);
  return bitcoin.script.compile(instructions);
};

test("check controlBlock exists ", (t) => {
  let content_type = "text/plain;charset=utf-8";
  let body = Buffer.from("999");
  const inscription = {
    body: body,
    content_type,
  };
  const network = bitcoin.networks.bitcoin;
  const internalKey = bip32.fromSeed(rng(64), bitcoin.networks.bitcoin);

  const tweakInternalPubKey = toXOnly(internalKey.publicKey);

  const randKey = bip32.fromSeed(rng(64), bitcoin.networks.bitcoin);

  const pubKeyChunks = bitcoin.script.compile([
    tweakInternalPubKey,
    bitcoin.opcodes.OP_CHECKSIG,
  ]);

  const revealScript = appendRevealScript(inscription);

  const revealScriptWithCheckSig = bitcoin.script.compile([
    pubKeyChunks,
    revealScript,
  ]);

  const scriptTree = {
    output: revealScriptWithCheckSig,
  };
  bitcoin.initEccLib(ecc);

  //taproot_spend_info
  const { output, witness } = bitcoin.payments.p2tr({
    internalPubkey: toXOnly(internalKey.publicKey),
    scriptTree,
    network: network,
  });

  if (!output) {
    console.log("no output");
    return;
  }
  //const payment = createPaymentP2tr(pubkeys, redeemIndex);

  let commitTxAddress = Bitcoin.address.fromOutputScript(output, network);

  console.log(commitTxAddress, output, witness, "p2tr");
  //const tapMerkleRoot = hash;
  if (!witness) {
    console.log("no witness");
    return;
  }
  const controlBlock = witness[witness.length - 1];

  console.log(controlBlock, witness);
});
