//! Certifier contract, taken from ethcore/sms-verification
//! By Gav Wood (Ethcore), 2016.
//! Released under the Apache Licence 2.

pragma solidity ^0.4.13;

contract Owned {
    modifier only_owner { if (msg.sender != owner) return; _; }

    event NewOwner(address indexed old, address indexed current);

    function setOwner(address _new) only_owner { NewOwner(owner, _new); owner = _new; }

    address public owner = msg.sender;
}

contract Certifier {
	event Confirmed(address indexed who);
	event Revoked(address indexed who);
	function certified(address _who) constant returns (bool);
	function getData(address _who, string _field) constant returns (bytes32) {}
	function getAddress(address _who, string _field) constant returns (address) {}
	function getUint(address _who, string _field) constant returns (uint) {}
}

contract MasterCertifier is Owned {
	function addCertifier(Certifier _who) public only_owner {
		for (uint i = 0; i < certifiers.length; ++i) {
			if (certifiers[i] == Certifier(0)) {
				certifiers[i] = _who;
				return;
			}
		}
		certifiers.push(_who);
	}

	function removeCertifier(Certifier _who) public only_owner returns (bool) {
		for (uint i = 0; i < certifiers.length; ++i) {
			if (certifiers[i] == _who) {
				certifiers[i] = Certifier(0);
				return true;
			}
		}
		return false;
	}

	function certified(address _who) public constant returns (bool) {
		for (uint i = 0; i < certifiers.length; ++i) {
			if (certifiers[i].certified(_who)) {
				return true;
			}
		}
		return false;
	}
	function getData(address _who, string _field) public constant returns (bytes32) {
		for (uint i = 0; i < certifiers.length; ++i) {
			if (certifiers[i].certified(_who)) {
				return certifiers[i].getData(_who, _field);
			}
		}
	}
	function getAddress(address _who, string _field) public constant returns (address) {
		for (uint i = 0; i < certifiers.length; ++i) {
			if (certifiers[i].certified(_who)) {
				return certifiers[i].getAddress(_who, _field);
			}
		}
	}
	function getUint(address _who, string _field) public constant returns (uint) {
		for (uint i = 0; i < certifiers.length; ++i) {
			if (certifiers[i].certified(_who)) {
				return certifiers[i].getUint(_who, _field);
			}
		}
	}

	Certifier[] public certifiers;
}
