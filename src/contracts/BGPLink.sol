pragma solidity ^0.5.7;

contract FunctionDiscovery {
    mapping (address => bool) public ownerList;
    mapping (uint256 => address) public functions;
    function getFunction(uint256 functionNameHash) public view returns (address) {}
    function setFunction(uint256 functionNameHash, address contractID) public {}
    function addOwner(address owner) public {}
    function removeOwner(address owner) public {}
}

contract IANA {
    mapping (address => bool) public ownerList;
    mapping (uint32 => address) public ASNList;
    function IANA_getASNOwner(uint32 ASN) public view returns (address) {}
    function IANA_addASN(uint32 ASN, address ASNOwner, uint8 sigV, bytes32 sigR, bytes32 sigS) public {}
    function IANA_removeASN(uint32 ASN, address ASNOwner, uint8 sigV, bytes32 sigR, bytes32 sigS) public {}
    function IANA_addOwner(address owner) public {}
    function IANA_removeOwner(address owner) public {}
}

/// A database for storing and verifying the presence of links
/// between two ASes without the need for direct interactivity between them.
/// For information about how to generate the necessary signatures, see
/// https://ethereum.stackexchange.com/a/30324

/// @author John-Michael O'Brien
/// @title Link Database

contract LinkDatabase {
    //address DISCOVERY_CONTRACT_ADDRESS = address(0x8C4D7453fAe2BA6D56B8b625A74Cf6c8C4207C03);
    address DISCOVERY_CONTRACT_ADDRESS = address(0x8c1ed7e19abaa9f23c476da86dc1577f1ef401f5);
    
    // Holds the table of links keyed by sha256(encodePacked(ASN1,ASN2))
    // A link is valid if both ASN1->ASN2 and ASN2->ASN1 exist.
    // This particular structure has the potential to be astoundingly large.
    mapping (bytes32 => bool) links;
    
    function getASNOwner(uint32 ASN) internal view returns (address) {
        // Get the Function Discovery contract
        FunctionDiscovery discovery = FunctionDiscovery(DISCOVERY_CONTRACT_ADDRESS);
        // Get the address of the IANA contract
        IANA iana_contract = IANA(discovery.getFunction(uint256(sha256("IANA_getASNOwner"))));
        // Get the public address of the ASN owner
        return iana_contract.IANA_getASNOwner(ASN);
    }

    /// Returns the contract address of the contact that contains the desired function.
    /// @param AS1 The ASN of the first end of the link
    /// @param AS2 The ASN of the first end of the link
    /// @return bool True if there is a valid, bidirectional link from AS1 to AS2
    function link_validateLink(uint32 AS1, uint32 AS2) public view returns (bool) {
        // Make the hash for the link in the forward direction
        bytes32 linkhash1 = sha256(abi.encodePacked(AS1, AS2));
        // Make the hash for the link in the reverse direction
        bytes32 linkhash2 = sha256(abi.encodePacked(AS2, AS1));
        // Return true if both links are in the valid link table.
        return links[linkhash1] && links[linkhash2];
    }

    /// Marks that the caller believes it has a link to a particular destination ASN.
    /// @param myASN The ASN the caller owns
    /// @param destinationASN The ASN that the caller links to.
    function link_addLink(uint32 myASN, uint32 destinationASN) public {
        require(msg.sender == getASNOwner(myASN));
        bytes32 linkhash = sha256(abi.encodePacked(myASN, destinationASN));
        links[linkhash] = true;
    }

    /// Marks that the caller believes it no longer has a link to a particular destination ASN.
    /// @param myASN The ASN the caller owns
    /// @param destinationASN The ASN that the caller links to.
    function link_removeLink(uint32 myASN, uint32 destinationASN) public {
        require(msg.sender == getASNOwner(myASN));
        bytes32 linkhash = sha256(abi.encodePacked(myASN, destinationASN));
        links[linkhash] = true;
    }
}