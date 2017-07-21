//sol Wallet
// Multi-sig, daily-limited account proxy/wallet.
// @authors:
// Gav Wood <g@ethdev.com>
// inheritable "property" contract that enables methods to be protected by requiring the acquiescence of either a
// single, or, crucially, each of a number of, designated owners.
// usage:
// use modifiers onlyowner (just own owned) or onlymanyowners(hash), whereby the same hash must be provided by
// some number (specified in constructor) of the set of owners (specified in the constructor, modifiable) before the
// interior is executed.

pragma solidity ^0.4.7;

contract multiowned {

	// FIELDS
	uint public m_required; // the number of owners needed to confirm.
	uint public m_numOwners; // pointer used to find a free slot in m_owners

	uint[256] m_owners; // owner array
	uint constant c_maxOwners = 250; // maximum number of owners allowed to avoid overflow
	mapping(uint => uint) m_ownerIndex; // index on the list of owners to allow reverse lookup
	mapping(bytes32 => PendingState) m_pending; // pending authorization map
	bytes32[] m_pendingIndex;

	// TYPES

	// struct for the status of a pending operation.
	struct PendingState {
		uint yetNeeded;
		uint ownersDone;
		uint index;
	}

	// EVENTS

	event Confirmation(address owner, bytes32 operation); //record confirmation with owner and hash
	event Revoke(address owner, bytes32 operation); //record revocation with owner and hash
	event OwnerChanged(address oldOwner, address newOwner); //owner change
	event OwnerAdded(address newOwner); // owner addition
	event OwnerRemoved(address oldOwner); // owner removal
	event RequirementChanged(uint newRequirement); //if number of sigs change

	// MODIFIERS

	modifier onlyowner {
		if (isOwner(msg.sender))
			_;
	}

	//_operation is a hash to confirm transaction with others using same hash
	modifier onlymanyowners(bytes32 _operation) {
		if (confirmAndCheck(_operation))
			_;
	}

	// METHODS

	/// @dev Constructor
	/// @param _owners Array of authorized addresses
	/// @param _required Number of sigs required
	function multiowned(address[] _owners, uint _required) {
		require(_required > 0);
		require(_owners.length >= _required);
		m_numOwners = _owners.length;
		for (uint i = 0; i < _owners.length; ++i) {
			m_owners[1 + i] = uint(_owners[i]);
			m_ownerIndex[uint(_owners[i])] = 1 + i;
		}
		m_required = _required;
	}

	/// @dev Revokes approval from authorized address
	/// @param _operation Hash of the operation to revoke
	function revoke(bytes32 _operation) external {
		uint ownerIndex = m_ownerIndex[uint(msg.sender)];
		// make sure they're an owner
		if (ownerIndex == 0) return;
		uint ownerIndexBit = 2**ownerIndex;
		var pending = m_pending[_operation];
		if (pending.ownersDone & ownerIndexBit > 0) {
			pending.yetNeeded++;
			pending.ownersDone -= ownerIndexBit;
			Revoke(msg.sender, _operation);
		}
	}

	/// @dev Change owner address
	/// @param _from Old address to replace
	/// @param _to New address
	function changeOwner(address _from, address _to) onlymanyowners(sha3(msg.data)) external {
		if (isOwner(_to)) return;
		uint ownerIndex = m_ownerIndex[uint(_from)];
		if (ownerIndex == 0) return;

		clearPending();
		m_owners[ownerIndex] = uint(_to);
		m_ownerIndex[uint(_from)] = 0;
		m_ownerIndex[uint(_to)] = ownerIndex;
		OwnerChanged(_from, _to);
	}

	/// @dev Add new owner
	/// @param _owner Address to add
	function addOwner(address _owner) onlymanyowners(sha3(msg.data)) external {
		if (isOwner(_owner)) return;

		clearPending();
		if (m_numOwners >= c_maxOwners)
			reorganizeOwners();
		if (m_numOwners >= c_maxOwners)
			return;
		m_numOwners++;
		m_owners[m_numOwners] = uint(_owner);
		m_ownerIndex[uint(_owner)] = m_numOwners;
		OwnerAdded(_owner);
	}

	/// @dev Remove an owner
	/// @param _owner Address to remove
	function removeOwner(address _owner) onlymanyowners(sha3(msg.data)) external {
		uint ownerIndex = m_ownerIndex[uint(_owner)];
		if (ownerIndex == 0) return;
		if (m_required > m_numOwners - 1) return;

		m_owners[ownerIndex] = 0;
		m_ownerIndex[uint(_owner)] = 0;
		clearPending();
		//make sure m_numOwner is equal to the number of owners and always points to the optimal free slot
		reorganizeOwners();
		OwnerRemoved(_owner);
	}

	/// @dev Change the number of approvals required
	/// @param _newRequired New number of approvals required
	function changeRequirement(uint _newRequired) onlymanyowners(sha3(msg.data)) external {
		if (_newRequired == 0) return;
		if (_newRequired > m_numOwners) return;
		m_required = _newRequired;
		clearPending();
		RequirementChanged(_newRequired);
	}

	/// @dev Gets an owner by 0-indexed position (using numOwners as the count)
	/// @param ownerIndex Index of owner to retrieve
	/// @return Address of owner
	function getOwner(uint ownerIndex) external constant returns (address) {
		return address(m_owners[ownerIndex + 1]);
	}

	/// @dev Query if an address is an owner
	/// @param _addr address to check
	/// @return True if owner, false otherwise
	function isOwner(address _addr) returns (bool) {
		return m_ownerIndex[uint(_addr)] > 0;
	}

	/// @dev Query if owner has confirmed a transaction by hash
	/// @param _operation Operation hash to check
	/// @param _owner Address of owner to check
	/// @return True if confirmed, false otherwise
	function hasConfirmed(bytes32 _operation, address _owner) constant returns (bool) {
		var pending = m_pending[_operation];
		uint ownerIndex = m_ownerIndex[uint(_owner)];

		if (ownerIndex == 0) return false;

		// determine the bit to set for this owner.
		uint ownerIndexBit = 2**ownerIndex;
		return !(pending.ownersDone & ownerIndexBit == 0);
	}

	// INTERNAL METHODS

	/// @dev Confirm authorization
	/// @param _operation Hash of operation to confirm
	/// @return True if number of confirmations reached, false otherwise
	function confirmAndCheck(bytes32 _operation) internal returns (bool) {
		uint ownerIndex = m_ownerIndex[uint(msg.sender)]; // determine what index the present sender is
		if (ownerIndex == 0) return;

		var pending = m_pending[_operation];
		// if we're not yet working on this operation, switch over and reset the confirmation status.
		if (pending.yetNeeded == 0) {
			pending.yetNeeded = m_required; // reset count of confirmations needed.
			pending.ownersDone = 0; // reset which owners have confirmed (none) - set our bitmap to 0
			pending.index = m_pendingIndex.length++;
			m_pendingIndex[pending.index] = _operation;
		}

		uint ownerIndexBit = 2**ownerIndex; // determine the bit to set for this owner.
		// make sure we (the message sender) haven't confirmed this operation previously.
		if (pending.ownersDone & ownerIndexBit == 0) {
			Confirmation(msg.sender, _operation);
			// ok - check if count is enough to go ahead.
			if (pending.yetNeeded <= 1) {
				// enough confirmations: reset and run interior.
				delete m_pendingIndex[m_pending[_operation].index];
				delete m_pending[_operation];
				return true;
			}
			else
			{
				// not enough: record that this owner in particular confirmed.
				pending.yetNeeded--;
				pending.ownersDone |= ownerIndexBit;
			}
		}
	}

	/// @dev Organize owner array after a removal
	function reorganizeOwners() private {
		uint free = 1;
		while (free < m_numOwners)
		{
			while (free < m_numOwners && m_owners[free] != 0) free++;
			while (m_numOwners > 1 && m_owners[m_numOwners] == 0) m_numOwners--;
			if (free < m_numOwners && m_owners[m_numOwners] != 0 && m_owners[free] == 0)
			{
				m_owners[free] = m_owners[m_numOwners];
				m_ownerIndex[m_owners[free]] = free;
				m_owners[m_numOwners] = 0;
			}
		}
	}

	/// @dev Clear a pending authorization
	function clearPending() internal {
		uint length = m_pendingIndex.length;
		for (uint i = 0; i < length; ++i)
			if (m_pendingIndex[i] != 0)
				delete m_pending[m_pendingIndex[i]];
		delete m_pendingIndex;
	}
}

// inheritable "property" contract that enables methods to be protected by placing a linear limit (specifiable)
// on a particular resource per calendar day. is multiowned to allow the limit to be altered. resource that method
// uses is specified in the modifier.
contract daylimit is multiowned {

	// FIELDS

	uint public m_dailyLimit;
	uint public m_spentToday;
	uint public m_lastDay;

	// EVENTS

	ErrMsg(address _spender, string msg);

	// METHODS

	/// @dev Constructor - stores initial daily limit and records the present day's index.
	/// @param _limit Daily limit of resource
	function daylimit(uint _limit) {
		m_dailyLimit = _limit;
		m_lastDay = today();
	}

	/// @dev Sets new daily limit, needs m_required number of owners to confirm.
	/// @param _newLimit New daily limit
	function setDailyLimit(uint _newLimit) onlymanyowners(sha3(msg.data)) external {
		m_dailyLimit = _newLimit;
	}

	/// @dev Sets day spend to zero, needs m_required number of owners to confirm.
	function resetSpentToday() onlymanyowners(sha3(msg.data)) external {
		m_spentToday = 0;
	}

	// INTERNAL METHODS

	/// @dev Checks if _value to spend is within bounds if there is, subtracts it and
	/// @param _value Amount to be spent
	/// @return True if in bounds, false otherwise
	function underLimit(uint _value) internal onlyowner returns (bool) {
		// reset the spend limit if we're on a different day to last time.
		if (today() > m_lastDay) {
			m_spentToday = 0;
			m_lastDay = today();
		}

		// overflow protection                    // dailyLimit check
		if (m_spentToday + _value >= m_spentToday && m_spentToday + _value <= m_dailyLimit) {
			m_spentToday += _value;
			return true;
		}
		return false;
	}

	/// @dev Utility function, determines today's index.
	function today() private constant returns (uint) { return now / 1 days; }
}

// interface contract for multisig proxy contracts; see below for docs.
contract multisig {

	// EVENTS

	// logged events:
	// Funds has arrived into the wallet (record how much).
	event Deposit(address _from, uint value);
	// Single transaction going out of the wallet (record who signed for it, how much, and to whom it's going).
	event SingleTransact(address owner, uint value, address to, bytes data, address created);
	// Multi-sig transaction going out of the wallet (record who signed for it last, the operation hash, how much, and to whom it's going).
	event MultiTransact(address owner, bytes32 operation, uint value, address to, bytes data, address created);
	// Confirmation still needed for a transaction.
	event ConfirmationNeeded(bytes32 operation, address initiator, uint value, address to, bytes data);

	// FUNCTIONS

	// TODO: document
	function changeOwner(address _from, address _to) external;
	function execute(address _to, uint _value, bytes _data) external returns (bytes32 o_hash);
	function confirm(bytes32 _h) returns (bool o_success);
}

contract creator {
	function doCreate(uint _value, bytes _code) internal returns (address o_addr) {
		bool failed;
		assembly {
			o_addr := create(_value, add(_code, 0x20), mload(_code))
			failed := iszero(extcodesize(o_addr))
		}
		require(!failed);
	}
}

// usage:
// bytes32 h = Wallet(w).from(oneOwner).execute(to, value, data);
// Wallet(w).from(anotherOwner).confirm(h);
contract Wallet is multisig, multiowned, daylimit, creator {

	// FIELDS

	mapping (bytes32 => Transaction) m_txs; // pending transactions we have at present

	// TYPES

	// Transaction structure to remember details of transaction lest it need be saved for a later call.
	struct Transaction {
		address to;
		uint value;
		bytes data;
	}

	// METHODS

	/// @dev Constructor
	/// @param _owners Array of owner addresses
	/// @param _required Number of confirmations required for changes
	/// @param _dayLimit Limit of resource spend per day
	function Wallet(address[] _owners, uint _required, uint _daylimit)
			multiowned(_owners, _required) daylimit(_daylimit) {
	}

	/// @dev Destroys wallet
	/// @param _to Address to send rest of resource to
	function kill(address _to) onlymanyowners(sha3(msg.data)) external {
		suicide(_to);
	}

	/// @dev Fallback function, is payable
	function() payable {
		if (msg.value > 0)
			Deposit(msg.sender, msg.value);
	}

	/// @dev Executes a transaction, immediately if in spend bounds, returns _operation hash
	/// for others to confirm if above spend limit
	/// @param _to Address of resource recipient, 0 if new contract is recipient
	/// @param _value Amount to spend
	/// @param _data Data for recipient function
	/// @return o_hash Operation hash for others to use if m_required owners needed to confirm
	function execute(address _to, uint _value, bytes _data) external onlyowner returns (bytes32 o_hash) {
		// first, take the opportunity to check that we're under the daily limit.
		if ((_data.length == 0 && underLimit(_value)) || m_required == 1) {
			// yes - just execute the call.
			address created;
			if (_to == 0) {
				created = create(_value, _data);
			} else {
				require(_to.call.value(_value)(_data));
			}
			SingleTransact(msg.sender, _value, _to, _data, created);
		} else {
			// determine our operation hash.
			o_hash = sha3(msg.data, block.number);
			// store if it's new
			if (m_txs[o_hash].to == 0 && m_txs[o_hash].value == 0 && m_txs[o_hash].data.length == 0) {
				m_txs[o_hash].to = _to;
				m_txs[o_hash].value = _value;
				m_txs[o_hash].data = _data;
			}
			if (!confirm(o_hash)) {
				ConfirmationNeeded(o_hash, msg.sender, _value, _to, _data);
			}
		}
	}

  /// @dev Used to confirm transaction by msg.sender using hash
  /// @param Hash of operation to confirm
  /// @return o_success True if transaction is complete, false if more confirms needed
  function confirm(bytes32 _h) onlymanyowners(_h) returns (bool o_success) {
    if (m_txs[_h].to != 0 || m_txs[_h].value != 0 || m_txs[_h].data.length != 0) {
      address created;
      if (m_txs[_h].to == 0) {
        created = create(m_txs[_h].value, m_txs[_h].data);
      } else {
        require(m_txs[_h].to.call.value(m_txs[_h].value)(m_txs[_h].data));
      }

      MultiTransact(msg.sender, _h, m_txs[_h].value, m_txs[_h].to, m_txs[_h].data, created);
      delete m_txs[_h];
      return true;
    }
  }

	// INTERNAL METHODS

  /// @dev Creates new contract
  /// @param _value Amount to send
  /// @param _code Code for new contract
  /// @return o_addr Address of new contract
  function create(uint _value, bytes _code) internal returns (address o_addr) {
    return doCreate(_value, _code);
  }

	/// @dev Clears pending transaction
	function clearPending() internal {
		uint length = m_pendingIndex.length;
		for (uint i = 0; i < length; ++i)
			delete m_txs[m_pendingIndex[i]];
		super.clearPending();
	}

}
