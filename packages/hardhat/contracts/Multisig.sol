//SPDX-License-Identifier: MIT

pragma solidity >=0.8.0 <0.9.0;
import "hardhat/console.sol";
// import "@openzeppelin/contracts/access/Ownable.sol"; 
// https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/Ownable.sol
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";


contract Multisig {
  using ECDSA for bytes32;

  uint256 public s_signaturesRequired;
  uint public nonce;
  uint public chainId;

  mapping(address => bool) public s_isOwner;

  event Owner(address indexed owner, bool added);
  event SubmitTransaction(address indexed sender, uint256 indexed  txIndex, address indexed to, uint256 value, bytes data);
  event Deposit(address indexed sender, uint256 amount, uint256 balance);
  event ExecuteTransaction(address indexed owner, address payable to, uint256 value, bytes data, uint256 nonce, bytes32 hash, bytes result);

    modifier onlyOwner() {
        require(s_isOwner[msg.sender], "not owner");
        _;
    }

    modifier onlySelf() {
      require(msg.sender == address(this), "Not self");
      _;
    }



  constructor(uint256 _chainId, uint _signaturesRequired, address[] memory _owners) {
    chainId = _chainId;    
    require(_signaturesRequired > 0, "constructor: must be non-zero signatures required");
    s_signaturesRequired = _signaturesRequired;
    for (uint i = 0; i < _owners.length; i++) {
      address owner = _owners[i];
      require(!s_isOwner[owner], "already owner");
      require(owner != address(0), "Zero address");
      s_isOwner[owner] = true;
      emit Owner(owner, s_isOwner[owner]);
    }
    chainId = _chainId;

  }

  function getTransactionHash(uint256 _nonce, address to, uint256 value, bytes memory data) public view returns (bytes32) {
    return keccak256(abi.encodePacked(address(this), chainId, _nonce, to, value, data));
  }


  function executeTransaction(address payable to, uint256 value, bytes memory data, bytes[] memory signatures)
      public
      onlyOwner returns (bytes memory)
  {
    bytes32 _hash = getTransactionHash(nonce, to, value, data);
    nonce++;
    uint256 validSignatures;
    address duplicateGuard;
    for (uint i = 0; i < signatures.length; i++) {
      address recovered = recover(_hash, signatures[i]);
      require(recovered < duplicateGuard, "executeTransaction: duplicate or unordered signatures");
      duplicateGuard = recovered;
      if(s_isOwner[recovered]) validSignatures++;
    }

    require (validSignatures >= s_signaturesRequired, "executeTransaction: not enough valid signatures");

    (bool success, bytes memory result) = to.call{value: value}(data);
    require(success, "executeTransaction: tx failed");
    
              emit ExecuteTransaction(msg.sender, to, value, data, nonce-1, _hash, result);
              return result;
  }
  
  function recover(bytes32 _hash, bytes memory _signature) public pure returns (address) {
    return _hash.toEthSignedMessageHash().recover(_signature);
  }

  // to support receiving ETH by default
  receive() external payable {}
  fallback() external payable {
    emit Deposit(msg.sender, msg.value, address(this).balance);
  }
}
