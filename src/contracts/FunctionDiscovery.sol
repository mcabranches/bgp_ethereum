pragma solidity ^0.5.7;

/// A function discovery database. Allows for functions to exist in multiple
/// contracts, and for function updates to be done without updating the calling
/// contracts. Though by default it accepts updates from its creator, new admins
/// can be added and old ones removed. This allows for the future implementation
/// of voting and consensus contracts for version updates. Simply add the
/// consensus contract as an admin, and remove the original owner.

/// @author John-Michael O'Brien
/// @title Function Discovery Database

contract FunctionDiscovery {
    // All the people who can change the function pointers
    mapping (address => bool) public ownerList;
    // The list of contracts associated with the 
    mapping (uint256 => address) public functions;

    /// Simple modifier to ensure that only owners can make changes
    modifier onlyOwners {
        require(ownerList[msg.sender] == true);
        _;
    }

    constructor() public {
        // Automatically add the contract creator as an owner
        ownerList[msg.sender] = true;
    }
    
    /// Returns the contract address of the contact that contains the desired function.
    /// @param functionNameHash The SHA256 hash of the function name to be called, including any decorators for disambiguation.
    /// @return Address to the contract where the function can be found
    function getFunction(uint256 functionNameHash) public view returns (address) {
        return functions[functionNameHash];
    }
    
    /// Adds the function to the function table, or updates it to a new value.
    /// @param functionNameHash The SHA256 hash of the function name to be called, including any decorators for disambiguation.
    /// @param contractID The address of the contract that contains the most up to date version of the function.
    function setFunction(uint256 functionNameHash, address contractID) public onlyOwners {
        functions[functionNameHash] = contractID;
    }

    /// Adds an additional user to the owners table, allowing them to modify the discovery tables.
    /// @param owner The public key of the new owner.
    function addOwner(address owner) public onlyOwners {
        ownerList[owner] = true;
    }

    /// Removes a user from the owners table, who will no longer be allowed to edit the discovery table.
    /// @param owner The public key of the owner to be removed.
    function removeOwner(address owner) public onlyOwners {
        delete(ownerList[owner]);
    }
}
