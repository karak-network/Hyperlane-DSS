/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { Signer, utils, Contract, ContractFactory, Overrides } from "ethers";
import { Provider, TransactionRequest } from "@ethersproject/providers";
import type { TestQueue, TestQueueInterface } from "../TestQueue";

const _abi = [
  {
    inputs: [],
    stateMutability: "nonpayable",
    type: "constructor",
  },
  {
    inputs: [
      {
        internalType: "bytes32",
        name: "_item",
        type: "bytes32",
      },
    ],
    name: "contains",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "dequeue",
    outputs: [
      {
        internalType: "bytes32",
        name: "_item",
        type: "bytes32",
      },
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint256",
        name: "_number",
        type: "uint256",
      },
    ],
    name: "dequeueMany",
    outputs: [
      {
        internalType: "bytes32[]",
        name: "_items",
        type: "bytes32[]",
      },
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [],
    name: "drain",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes32",
        name: "_item",
        type: "bytes32",
      },
    ],
    name: "enqueue",
    outputs: [
      {
        internalType: "uint256",
        name: "_last",
        type: "uint256",
      },
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes32[]",
        name: "_items",
        type: "bytes32[]",
      },
    ],
    name: "enqueueMany",
    outputs: [
      {
        internalType: "uint256",
        name: "_last",
        type: "uint256",
      },
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [],
    name: "initializeAgain",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [],
    name: "lastItem",
    outputs: [
      {
        internalType: "bytes32",
        name: "",
        type: "bytes32",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "length",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "peek",
    outputs: [
      {
        internalType: "bytes32",
        name: "_item",
        type: "bytes32",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes32",
        name: "_item",
        type: "bytes32",
      },
    ],
    name: "queueContains",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "queueEnd",
    outputs: [
      {
        internalType: "bytes32",
        name: "",
        type: "bytes32",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "queueLength",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
];

const _bytecode =
  "0x608060405234801561001057600080fd5b506109c5806100206000396000f3fe608060405234801561001057600080fd5b50600436106100df5760003560e01c80638f2cbe701161008c578063a9541aa211610066578063a9541aa21461022e578063ab91c7b014610115578063b4de3e2314610236578063f6d161021461012f576100df565b80638f2cbe70146101ac578063957908d11461021c5780639890220b14610224576100df565b80632bef2892116100bd5780632bef2892146100e457806359e02dd7146101375780635b8b49591461013f576100df565b80631d1a696d146100e45780631f7b6d3214610115578063210ce6b91461012f575b600080fd5b610101600480360360208110156100fa57600080fd5b5035610253565b604080519115158252519081900360200190f35b61011d610266565b60408051918252519081900360200190f35b61011d610277565b61011d610283565b61015c6004803603602081101561015557600080fd5b503561028f565b60408051602080825283518183015283519192839290830191858101910280838360005b83811015610198578181015183820152602001610180565b505050509050019250505060405180910390f35b61011d600480360360208110156101c257600080fd5b8101906020810181356401000000008111156101dd57600080fd5b8201836020820111156101ef57600080fd5b8035906020019184602083028401116401000000008311171561021157600080fd5b50909250905061029c565b61011d6102f7565b61022c610303565b005b61022c610324565b61011d6004803603602081101561024c57600080fd5b503561032e565b6000610260600183610353565b92915050565b600061027260016103cd565b905090565b6000610272600161040d565b6000610272600161044a565b60606102606001836104eb565b60006102de83838080602002602001604051908101604052809392919081815260200183836020028082843760009201919091525060019392505061069b9050565b6fffffffffffffffffffffffffffffffff169392505050565b6000610272600161075b565b61030d60016103cd565b156103225761031c600161075b565b50610303565b565b6103226001610894565b600061033b6001836108d9565b6fffffffffffffffffffffffffffffffff1692915050565b81546000906fffffffffffffffffffffffffffffffff165b835470010000000000000000000000000000000090046fffffffffffffffffffffffffffffffff1681116103c35760008181526001850160205260409020548314156103bb576001915050610260565b60010161036b565b5060009392505050565b80546000906fffffffffffffffffffffffffffffffff7001000000000000000000000000000000008204811691166104058282610946565b949350505050565b805470010000000000000000000000000000000090046fffffffffffffffffffffffffffffffff1660009081526001909101602052604090205490565b600061045582610960565b156104c157604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152600560248201527f456d707479000000000000000000000000000000000000000000000000000000604482015290519081900360640190fd5b5080546fffffffffffffffffffffffffffffffff1660009081526001909101602052604090205490565b81546060906fffffffffffffffffffffffffffffffff700100000000000000000000000000000000820481169116836105248383610946565b101561059157604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152600c60248201527f496e73756666696369656e740000000000000000000000000000000000000000604482015290519081900360640190fd5b60008467ffffffffffffffff811180156105aa57600080fd5b506040519080825280602002602001820160405280156105d4578160200160208202803683370190505b50905060005b85811015610652576fffffffffffffffffffffffffffffffff83166000908152600188016020526040902054825183908390811061061457fe5b6020908102919091018101919091526fffffffffffffffffffffffffffffffff841660009081526001808a01909252604081205592830192016105da565b5085547fffffffffffffffffffffffffffffffff00000000000000000000000000000000166fffffffffffffffffffffffffffffffff9290921691909117909455509192915050565b815470010000000000000000000000000000000090046fffffffffffffffffffffffffffffffff1660005b82518110156107275760018201915060008382815181106106e357fe5b602002602001015190506000801b811461071e576fffffffffffffffffffffffffffffffff8316600090815260018601602052604090208190555b506001016106c6565b5082546fffffffffffffffffffffffffffffffff808316700100000000000000000000000000000000029116179092555090565b80546000906fffffffffffffffffffffffffffffffff7001000000000000000000000000000000008204811691166107938282610946565b6107fe57604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152600560248201527f456d707479000000000000000000000000000000000000000000000000000000604482015290519081900360640190fd5b6fffffffffffffffffffffffffffffffff811660009081526001850160205260409020549250821561084f576fffffffffffffffffffffffffffffffff811660009081526001850160205260408120555b83547fffffffffffffffffffffffffffffffff00000000000000000000000000000000166001919091016fffffffffffffffffffffffffffffffff1617909255919050565b80546fffffffffffffffffffffffffffffffff166108d65780547fffffffffffffffffffffffffffffffff000000000000000000000000000000001660011781555b50565b81546fffffffffffffffffffffffffffffffff8082167001000000000000000000000000000000009283900482166001019182169092029190911783558115610260576fffffffffffffffffffffffffffffffff8116600090815260019390930160205260409092205590565b60019103016fffffffffffffffffffffffffffffffff1690565b546fffffffffffffffffffffffffffffffff80821670010000000000000000000000000000000090920416109056fea2646970667358221220c9573f7b751cc180ba9bed63c38074b0dbd4e6e90df44e2832e15cdbe824bb9564736f6c63430007060033";

export class TestQueue__factory extends ContractFactory {
  constructor(signer?: Signer) {
    super(_abi, _bytecode, signer);
  }

  deploy(
    overrides?: Overrides & { from?: string | Promise<string> }
  ): Promise<TestQueue> {
    return super.deploy(overrides || {}) as Promise<TestQueue>;
  }
  getDeployTransaction(
    overrides?: Overrides & { from?: string | Promise<string> }
  ): TransactionRequest {
    return super.getDeployTransaction(overrides || {});
  }
  attach(address: string): TestQueue {
    return super.attach(address) as TestQueue;
  }
  connect(signer: Signer): TestQueue__factory {
    return super.connect(signer) as TestQueue__factory;
  }
  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): TestQueueInterface {
    return new utils.Interface(_abi) as TestQueueInterface;
  }
  static connect(
    address: string,
    signerOrProvider: Signer | Provider
  ): TestQueue {
    return new Contract(address, _abi, signerOrProvider) as TestQueue;
  }
}