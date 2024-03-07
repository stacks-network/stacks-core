import { Cl, ClarityValue, serializeCV } from "@stacks/transactions";
import { createHash } from "crypto";

function sha256(data: Buffer): Buffer {
  return createHash("sha256").update(data).digest();
}

function structuredDataHash(structuredData: ClarityValue): Buffer {
  return sha256(Buffer.from(serializeCV(structuredData)));
}

const generateDomainHash = () =>
  Cl.tuple({
    name: Cl.stringAscii("pox-4-signer"),
    version: Cl.stringAscii("1.0.0"),
    "chain-id": Cl.uint(2147483648),
  });

const generateMessageHash = (
  version: number,
  hashbytes: number[],
  reward_cycle: number,
  topic: string,
  period: number,
  auth_id: number,
  max_amount: number
) =>
  Cl.tuple({
    "pox-addr": Cl.tuple({
      version: Cl.buffer(Uint8Array.from([version])),
      hashbytes: Cl.buffer(Uint8Array.from(hashbytes)),
    }),
    "reward-cycle": Cl.uint(reward_cycle),
    topic: Cl.stringAscii(topic),
    period: Cl.uint(period),
    "auth-id": Cl.uint(auth_id),
    "max-amount": Cl.uint(max_amount),
  });

const generateMessagePrefixBuffer = (prefix: string) =>
  Buffer.from(prefix, "hex");

export const buildSignerKeyMessageHash = (
  version: number,
  hashbytes: number[],
  reward_cycle: number,
  topic: string,
  period: number,
  max_amount: number,
  auth_id: number
) => {
  const sip018_msg_prefix = "534950303138";
  const domain_hash = structuredDataHash(generateDomainHash());
  const message_hash = structuredDataHash(
    generateMessageHash(
      version,
      hashbytes,
      reward_cycle,
      topic,
      period,
      auth_id,
      max_amount
    )
  );
  const structuredDataPrefix = generateMessagePrefixBuffer(sip018_msg_prefix);

  const signer_key_message_hash = sha256(
    Buffer.concat([structuredDataPrefix, domain_hash, message_hash])
  );

  return signer_key_message_hash;
};
