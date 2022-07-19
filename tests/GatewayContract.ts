export type Binary = string;
export type HumanAddr = string;

export interface PreExecutionMsg {
  handle: string;
  payload: Binary;
  payload_hash: Binary;
  payload_signature: Binary;
  routing_info: Contract;
  sender: Sender;
  task_id: number;
  [k: string]: unknown;
}
export interface Contract {
  address: HumanAddr;
  hash: string;
  [k: string]: unknown;
}
export interface Sender {
  address: HumanAddr;
  public_key: Binary;
  [k: string]: unknown;
}
export interface PostExecutionMsg {
  parameters: string;
  result: Binary;
  task_id: number;
  [k: string]: unknown;
}
export interface InitMsg {
  admin?: HumanAddr | null;
  entropy: string;
  [k: string]: unknown;
}
export interface Payload {
  data: string;
  routing_info: Contract;
  sender: Sender;
  [k: string]: unknown;
}