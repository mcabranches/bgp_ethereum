pragma solidity ^0.5.7;

contract IANA {
    struct Prefix {
        uint32 ip;
        uint8 mask;
        uint32 owningAS;
        uint[] subPrefixes; // Pointer to prefix index in the larger prefixes array.
    }
    
    enum PrefixCompareResult {
        OneConatinsTwo,
        TwoContainsOne,
        NoIntersection,
        Equal
    }
    
    // All the people who can change the function pointers
    mapping (address => bool) public ownerList;
    // The associative mapping that maps ASNs to their owner's public key.
    mapping (uint32 => address) public ASNList;
    // List of prefixes.
    Prefix[] public prefixes;
    // Holds the table of links keyed by sha256(encodePacked(ASN1,ASN2))
    // A link is valid if both ASN1->ASN2 and ASN2->ASN1 exist.
    // This particular structure has the potential to be astoundingly large.
    mapping (bytes32 => bool) links;


    /// Simple modifier to ensure that only owners can make changes
    modifier onlyOwners {
        require(ownerList[msg.sender] == true);
        _;
    }

    constructor() public {
        // Automatically add the contract creator as an owner
        ownerList[msg.sender] = true;
        
        // Build up the prefix for the root prefix
        Prefix memory rootPrefix;
        rootPrefix.ip = 0;
        rootPrefix.mask = 0;
        rootPrefix.owningAS = 0;
        prefixes.push(rootPrefix);

        // Mark that the root is owned by a dummy address.
        ASNList[0] = address(0);
    }

    /// Compares the address spaces of two prefixes and determines if they are the same, do not intersect, or if one contains another.
    /// @param ip1 IP Address of the first prefix
    /// @param mask1 Number of bits in the subnet mask for the first prefix
    /// @param ip2 IP Address of the second prefix
    /// @param mask2 Number of bits in the subnet mask for the second prefix
    /// @return PrefixCompareResult The relationship between the two sets of prefix data.
    function prefix_comparePrefix(uint32 ip1, uint8 mask1, uint32 ip2, uint8 mask2) public pure returns (PrefixCompareResult) {
        // Only valid subnet masks
        require (mask1 <= 32 && mask2 <= 32);
        // If their masks are the same
        if (mask1 == mask2) {
            // As are their IPs
            if ((ip1 >> (32-mask1)) == (ip2 >> (32-mask1))) {
                // Then they're the same.
                return PrefixCompareResult.Equal;
            }
        }
        
        // Get the number of bits we have to shift to remove the host from the address.
        uint8 shift;
        // We need to pick the one with the largest address space (smallest mask) since we're testing for containment.
        if (mask1 < mask2) {
            shift = (32 - mask1);
        } else {
            shift = (32 - mask2);
        }

        // Shift the two addresses over so we can look at their network address alone.
        uint32 network1 = ip1 >> shift;
        uint32 network2 = ip2 >> shift;
        
        // If they reference different networks, then there isn't an intersection.
        if (network1 != network2) {
            return PrefixCompareResult.NoIntersection;
        }

        // If they reference the same network, it means the bigger one contains the smaller one.
        if (mask1 < mask2) {
            return PrefixCompareResult.OneConatinsTwo;
        } else {
            return PrefixCompareResult.TwoContainsOne;            
        }
    }

    /// Alias function to get just the containingPrefix.
    /// @param startingPrefixIndex The index of the entry to use to start the search. Use 0 to select the root prefix (0.0.0.0/0)
    /// @param ip The IP address of the prefix to locate
    /// @param mask The number of bits in the netmask for the prefix to locate
    /// @return uint Index of the most specific, wholly containing prefix or 0 if it is not contained by the prefix at startingPrefixIndex
    function prefix_getContainingPrefix(uint startingPrefixIndex, uint32 ip, uint8 mask) public view returns (uint) {
        (uint containingPrefix, ) = prefix_getContainingPrefixAndParent(startingPrefixIndex, ip, mask);
        return containingPrefix;
    }

    /// Gets the most specific prefix that wholly contains or is exactly equal to the specified prefix as found in the prefixes database.
    /// @param startingPrefixIndex The index of the entry to use to start the search. Use 0 to select the root prefix (0.0.0.0/0)
    /// @param ip The IP address of the prefix to locate
    /// @param mask The number of bits in the netmask for the prefix to locate
    /// @return uint,uint Tuple containing (index of the most specific, wholly containing prefix or 0 if it is not contained by the prefix at startingPrefixIndex,
    /// @return the parent index of the containing prefix or 0 if it is not contained or is a child of the root.)
    function prefix_getContainingPrefixAndParent(uint startingPrefixIndex, uint32 ip, uint8 mask) public view returns (uint,uint) {
        // Only valid subnet masks
        require (mask <= 32);

        // Get a handle to our starting prefix.
        Prefix storage startingPrefix = prefixes[startingPrefixIndex];
        
        // If the prefix has been deleted and isn't root...
        if (startingPrefix.ip == 0 && startingPrefix.mask == 0 && startingPrefixIndex != 0) {
            // No match.
            return (0,0);
        }
        
        // Find out the relationship of ourselves to the prefix
        PrefixCompareResult comparison = prefix_comparePrefix(startingPrefix.ip, startingPrefix.mask, ip, mask);

        if (comparison == PrefixCompareResult.Equal) {
            // This is us. Return ourselves.
            return (startingPrefixIndex, startingPrefixIndex);
        } else if (comparison == PrefixCompareResult.NoIntersection) {
            // We don't have anything to do with this. Say we don't know.
            return (0,0);
        } else if (comparison == PrefixCompareResult.TwoContainsOne) {
            // The prefix is bigger than us, we don't contain it.
            return (0,0);
        }
        else {
            // At this point we know the unknown is contained in us. But we need more; is it owned by a subprefix? The best way to find out is to ask.
            for (uint i=0; i<startingPrefix.subPrefixes.length; i++) {
                uint testIndex = startingPrefix.subPrefixes[i];
                (uint result, uint parent) = prefix_getContainingPrefixAndParent(testIndex, ip, mask);
                // If this child reports that they know who contains it
                if (result != 0) {
                    // Check if the parent is the same as the result. If it is, they're a leaf node.
                    if (result == parent) {
                        // And that means we're their first parent, so return ourselves as the parent.
                        return (result, startingPrefixIndex);
                    } else {
                        // Otherwise, we're further up the tree, and that means we just pass the result along as-is.
                        return (result, parent);
                    }
                }
            }
            
            // If we know we contain it, but none of our children claimed it, then it's ours. Return ourselves.
            return (startingPrefixIndex,startingPrefixIndex);
        }
    }
    
    /// Adds the specified prefix to the prefix table. Must be done by the owner of the prefixes containing
    /// AS and must include the signature of the message returned by IANA_getPrefixSignatureMessage for the new AS.
    /// @param ip The IP address of the prefix to add
    /// @param mask The number of bits in the netmask of the prefix to add
    /// @param newOwnerAS The AS number to associate with the new prefix to.
    /// @param sigV The V parameter of the signature.
    /// @param sigR The R parameter of the signature.
    /// @param sigS The S parameter of the signature.
    function prefix_addPrefix(uint32 ip, uint8 mask, uint32 newOwnerAS, uint8 sigV, bytes32 sigR, bytes32 sigS) public {
        // Only valid subnet masks
        require (mask <= 32);
        // Get the ASN's owner
        address newOwnerAddress = ASNList[newOwnerAS];
        // The owning ASN must exist
        require (newOwnerAddress != address(0));
        // The owning ASN must have signed the message.
        require(ecrecover(IANA_getPrefixSignatureMessage(ip, mask, newOwnerAS, newOwnerAddress), sigV, sigR, sigS) == newOwnerAddress);

        // Find who owns the space this mask is in.
        uint parentIndex = prefix_getContainingPrefix(0,ip, mask);
        Prefix storage parent = prefixes[parentIndex];

        // Require that the public address calling us owns the AS that owns the parent prefix.
        // (i.e. you can't claim addresses on someone else's prefix)
        // If the parent's owningAS is 0, that means that we're making changes to the root. Check against our internal owner list.
        if (parent.owningAS == 0) {
            require (ownerList[msg.sender] == true);
        } else {
            // Otherwise, check that our sender is the AS's owner.
            require (msg.sender == ASNList[parent.owningAS]);
        }
        
        // Require that the parent contains us.
        require(!(parent.ip == ip && parent.mask == mask));

        // For every child,
        for (uint i=0; i<parent.subPrefixes.length; i++) {
            uint testIndex = parent.subPrefixes[i];
            Prefix memory child = prefixes[testIndex];
            PrefixCompareResult result = prefix_comparePrefix(child.ip, child.mask, ip, mask);
            // Require that we're not trying to take their prefix.
            require(result == PrefixCompareResult.NoIntersection);
        }
        
        Prefix memory newPrefix;
        newPrefix.ip = ip;
        newPrefix.mask = mask;
        newPrefix.owningAS = newOwnerAS;
        uint index = prefixes.push(newPrefix) - 1;
        // Add it to the list
        parent.subPrefixes.push(index);
    }
    
    /// Adds the specified prefix to the prefix table. Must be done by the owner of the prefixes containing
    /// AS and must include the signature of the message returned by IANA_getSignatureMessage for the new AS.
    /// @param ip The IP address of the prefix to add
    /// @param mask The number of bits in the netmask of the prefix to add
    function prefix_removePrefix(uint32 ip, uint8 mask) public {
        // Only valid subnet masks
        require (mask <= 32);

        // Find who owns the space this mask is in.
        (uint index, uint parentIndex) = prefix_getContainingPrefixAndParent(0,ip, mask);
        Prefix storage target = prefixes[index];
        Prefix storage parent = prefixes[parentIndex];

        // Require that the public address calling us owns the prefix
        // (i.e. you can't claim addresses on someone else's prefix)
        require (msg.sender == ASNList[target.owningAS]);
        
        // The prefix must exactly reference the listed prefix.
        require(prefix_comparePrefix(target.ip, target.mask, ip, mask) == PrefixCompareResult.Equal);
        
        // We only delete prefixes that have no children. They have to be deleted seperately.
        require(target.subPrefixes.length == 0);
        
        //Blank the prefix (since deleting it is impossible in the contract and doesn't help anything anyway.)
        Prefix memory blankPrefix;
        blankPrefix.ip = 0;
        blankPrefix.mask = 0;
        blankPrefix.owningAS = 0;
        prefixes[index] = blankPrefix;
        
        // This operation is EXPENSIVE. However, without it, the arrays could get long. Basically we're looking
        // for our specific child node in the parent, and once we find it, we're deleting it from the array and
        // shrinking the array down.
        for(uint i=0;i<parent.subPrefixes.length;i++) {
            Prefix storage child = prefixes[parent.subPrefixes[i]];
            if (child.ip == target.ip && child.mask == target.mask) {
                // Skip ahead one and start shifting the array left
                for(i=i+1;i<parent.subPrefixes.length;i++) {
                    parent.subPrefixes[i-1] = parent.subPrefixes[i];
                }
                // Shrink the array.
                parent.subPrefixes.length = parent.subPrefixes.length - 1;
            }
        }
    }


    /// Returns the owner's address for the given ASN, or 0 if no one owns the ASN.
    /// @param ASN The ASN whose owner is to be returned
    /// @return address The address of the owner.
    function IANA_getASNOwner(uint32 ASN) public view returns (address) {
        return ASNList[ASN];
    }
    
    /// Generates the message text to be signed for add authentication.
    /// @param ASN The ASN to be added
    /// @param ASNOwner The public key of the new owner.
    /// @return bytes32 The sha256 hash of abi.encodePacked(ASN,ASNOwner).
    function IANA_getSignatureMessage(uint32 ASN, address ASNOwner) pure public returns(bytes32) {
        return sha256(abi.encodePacked(ASN,ASNOwner));
    }
    
    /// Generates the message text to be signed for add authentication.
    /// @param ASN The ASN to be added
    /// @param ASNOwner The public key of the new owner.
    /// @return bytes32 The sha256 hash of abi.encodePacked(ASN,ASNOwner).
    function IANA_getPrefixSignatureMessage(uint32 ip, uint8 mask, uint32 ASN, address ASNOwner) pure public returns(bytes32) {
        return sha256(abi.encodePacked(ip, mask, ASN, ASNOwner));
    }
    
    /// Adds an additional ASN to the ASN list. The operation has to include a signature
    /// from the ASN owner signing sha256(abi.encodePacked(ASN,ASNOwner)) which can be
    /// generated by calling IANA_getSignatureMessage()
    /// @param ASN The ASN to be added
    /// @param ASNOwner The public key of the new owner.
    /// @param sigV The V parameter of the signature.
    /// @param sigR The R parameter of the signature.
    /// @param sigS The S parameter of the signature.
    function IANA_addASN(uint32 ASN, address ASNOwner, uint8 sigV, bytes32 sigR, bytes32 sigS) public onlyOwners {
        // It must be signed by the new ASNOwner. We don't have to check for the IANA owner because
        // the onlyOwners routine does that for us.
        require(ecrecover(IANA_getSignatureMessage(ASN, ASNOwner), sigV, sigR, sigS) == ASNOwner);
        require(ASN != 0);
        
        // At this point, we have two party agreement on ASN ownership. Add it to the ANSList.
        ASNList[ASN] = ASNOwner;
    }

    /// Removes an ASN to the ASN list. The operation has to include a signature
    /// from the ASN owner signing sha256(abi.encodePacked(ASN,ASNOwner)) which can be
    /// generated by calling IANA_getSignatureMessage()
    /// @param ASN The ASN to be added
    /// @param ASNOwner The public key of the new owner.
    /// @param sigV The V parameter of the signature.
    /// @param sigR The R parameter of the signature.
    /// @param sigS The S parameter of the signature.
    function IANA_removeASN(uint32 ASN, address ASNOwner, uint8 sigV, bytes32 sigR, bytes32 sigS) public onlyOwners {
        // Get hash of the packed message that was signed.
        bytes32 msghash = sha256(abi.encodePacked(ASN,ASNOwner));
        // It must be signed by the new ASNOwner. We don't have to check for the IANA owner because
        // the onlyOwners routine does that for us.
        require(ecrecover(msghash, sigV, sigR, sigS) == ASNOwner);
        require(ASN != 0);
        
        // At this point, we have two party agreement on ASN ownership. Mark the ASN as unowned
        ASNList[ASN] = address(0);
    }

    /// Adds an additional user to the owners table, allowing them to modify the discovery tables.
    /// @param owner The public key of the new owner.
    function IANA_addOwner(address owner) public onlyOwners {
        ownerList[owner] = true;
    }

    /// Removes a user from the owners table, who will no longer be allowed to edit the discovery table.
    /// @param owner The public key of the owner to be removed.
    function IANA_removeOwner(address owner) public onlyOwners {
        delete(ownerList[owner]);
    }
    
    /// Alias for IANA_prefixCheck to allow for compatibility.
    function prefixCheck(uint8 A, uint8 B, uint8 C, uint8 D, uint8 M, uint _asNumber ) public view returns (bool){
        return IANA_prefixCheck(A<<24|B<<16|C<<8|D,M,_asNumber);
    }
    
    /// Determines if a given prefix is owned by the specified AS.
    /// @param ip The IP address of the prefix to be checked.
    /// @param mask The mask of the prefix to be checked.
    /// @param asNumber the ASN of the AS we're checking the prefix against
    /// @return bool true if the prefix's address space is owned by the listed AS and that address space hasn't been sublet to another AS, false otherwise.
    function IANA_prefixCheck(uint32 ip, uint8 mask, uint asNumber) public view returns (bool) {
        // Check if the address is part of a prefix subset that has been transferred to another user.
        // This will involve going to the prefix keyed data structure and enumerating it's sub owners.
        // If not return a false.
        
        // At this point we know we own it, and know we haven't sold it.
        
        uint index = prefix_getContainingPrefix(0,ip,mask);
        
        // No hits is bad. This means it's in unallocated space.
        if (index == 0) {
            return false;
        }
        
        Prefix storage parent = prefixes[index];

        // If the topmost containing isn't our AS, then it's bad.
        if (parent.owningAS != asNumber) {
            return false;
        }
        
        // For every child, make sure there isn't a subprefix that intersects this prefix.
        for (uint i=0; i<parent.subPrefixes.length; i++) {
            uint testIndex = parent.subPrefixes[i];
            Prefix storage child = prefixes[testIndex];
            PrefixCompareResult result = prefix_comparePrefix(child.ip, child.mask, ip, mask);
            // Make sure there isn't 
            if (result != PrefixCompareResult.NoIntersection) {
                return false;
            }
        }

        return true;
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
        require(msg.sender == ASNList[myASN]);
        bytes32 linkhash = sha256(abi.encodePacked(myASN, destinationASN));
        links[linkhash] = true;
    }

    /// Marks that the caller believes it no longer has a link to a particular destination ASN.
    /// @param myASN The ASN the caller owns
    /// @param destinationASN The ASN that the caller links to.
    function link_removeLink(uint32 myASN, uint32 destinationASN) public {
        require(msg.sender == ASNList[myASN]);
        bytes32 linkhash = sha256(abi.encodePacked(myASN, destinationASN));
        links[linkhash] = false;
    }
}
