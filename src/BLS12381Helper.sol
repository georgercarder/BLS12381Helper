// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity ^0.8.17;

abstract contract BLS12381Helper {

    constructor() {}

    // g1.One
    bytes internal constant _g1One = hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";

    // g2.One
    bytes internal constant _g2One = hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";

    // neg
    bytes internal constant _g2NegOne = hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000d1b3cc2c7027888be51d9ef691d77bcb679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa0000000000000000000000000000000013fa4d4a0ad8b1ce186ed5061789213d993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed";

    function g1One() public pure returns(bytes memory) {
        return _g1One;
    }

    function g2One() public pure returns(bytes memory) { 
        return _g2One;
    }

    function g2NegOne() public pure returns(bytes memory) { 
        return _g2NegOne;
    }

    function _g1Add(bytes memory a, bytes memory b) internal view returns(bytes memory c) {
        bytes memory input = new bytes(256);
        assembly {
            mstore(input, 0) // set length = 0 for append
        }
        _append(input, a);
        _append(input, b);
        require(input.length == 256, "_g1Add malformed input");
        bool success;
        c = new bytes(128);
        assembly {
            success := staticcall(sub(gas(), 2000), 10, add(input, 32), 256, add(c, 32), 128)
        }
        if (!success) {
            assembly {
                let ptr := mload(0x40)
                let size := returndatasize()
                returndatacopy(ptr, 0, size)
                revert(ptr, size)
            }
        }
    }

    function _g1Mul(bytes memory point, uint256 scalar) internal view returns(bytes memory c) {
        (bytes memory input) = abi.encodePacked(point, scalar); 
        require(input.length == 160, "_g1Mul malformed input");
        bool success;
        c = new bytes(128);
        assembly {
            success := staticcall(sub(gas(), 2000), 11, add(input, 32), 160, add(c, 32), 128)
        }
        if (!success) {
            assembly {
                let ptr := mload(0x40)
                let size := returndatasize()
                returndatacopy(ptr, 0, size)
                revert(ptr, size)
            }
        }
    }

    function _g1MultiExp(bytes memory input) internal view returns(bytes memory c) {
        require(input.length % 160 == 0, "_g1MultiExp malformed input");
        bool success;
        c = new bytes(128);
        assembly {
            success := staticcall(sub(gas(), 2000), 12, add(input, 32), mload(input), add(c, 32), 128)
        }
        if (!success) {
            assembly {
                let ptr := mload(0x40)
                let size := returndatasize()
                returndatacopy(ptr, 0, size)
                revert(ptr, size)
            }
        }
    }

    function _g2Add(bytes memory a, bytes memory b) internal view returns(bytes memory c) {
        bytes memory input = new bytes(512);
        assembly {
            mstore(input, 0) // set length = 0 for append
        }
        _append(input, a);
        _append(input, b);
        require(input.length == 512, "_g2Add malformed input");
        bool success;
        c = new bytes(256);
        assembly {
            success := staticcall(sub(gas(), 2000), 13, add(input, 32), 512, add(c, 32), 256)
        }
        if (!success) {
            assembly {
                let ptr := mload(0x40)
                let size := returndatasize()
                returndatacopy(ptr, 0, size)
                revert(ptr, size)
            }
        }
    }

    function _g2Mul(bytes memory point, uint256 scalar) internal view returns(bytes memory c) {
        (bytes memory input) = abi.encodePacked(point, scalar); 
        require(input.length == 288, "_g2Mul malformed input");
        bool success;
        c = new bytes(256);
        assembly {
            success := staticcall(sub(gas(), 2000), 14, add(input, 32), 288, add(c, 32), 256)
        }
        if (!success) {
            assembly {
                let ptr := mload(0x40)
                let size := returndatasize()
                returndatacopy(ptr, 0, size)
                revert(ptr, size)
            }
        }
    }
    
    function _g2MultiExp(bytes memory input) internal view returns(bytes memory c) {
        require(input.length % 288 == 0, "_g2MultiExp malformed input");
        bool success;
        c = new bytes(256);
        assembly {
            success := staticcall(sub(gas(), 2000), 15, add(input, 32), mload(input), add(c, 32), 256)
        }
        if (!success) {
            assembly {
                let ptr := mload(0x40)
                let size := returndatasize()
                returndatacopy(ptr, 0, size)
                revert(ptr, size)
            }
        }
    }
    
    function _checkPairing(bytes memory input) internal view returns (bool) {
        require(input.length % 384 == 0, "_checkPairing malformed input");
        bytes memory res = new bytes(32);
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 16, add(input, 32), mload(input), add(res, 32), 32)
        }
        if (!success) {
            assembly {
                let ptr := mload(0x40)
                let size := returndatasize()
                returndatacopy(ptr, 0, size)
                revert(ptr, size)
            }
        }
        return res[31] != 0;
    }

    function _mapToG1(uint256 x, uint256 y) internal view returns(bytes memory ret) {
        (bytes memory input) = abi.encodePacked(x, y);
        ret = new bytes(128);
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 17, add(input, 32), 64, add(ret, 32), 128)
        }
        if (!success) {
            assembly {
                let ptr := mload(0x40)
                let size := returndatasize()
                returndatacopy(ptr, 0, size)
                revert(ptr, size)
            }
        }
    }

    function _mapToG2(uint256 c00, uint256 c01, uint256 c10, uint256 c11) internal view returns(bytes memory ret) {
        (bytes memory input) = abi.encodePacked(c00, c01, c10, c11);
        ret = new bytes(256);
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 18, add(input, 32), 128, add(ret, 32), 256)
        }
        if (!success) {
            assembly {
                let ptr := mload(0x40)
                let size := returndatasize()
                returndatacopy(ptr, 0, size)
                revert(ptr, size)
            }
        }
    }

    // cheaper than bytes concat :)
    function _append(bytes memory dst, bytes memory src) internal view {
      
        assembly {
            // resize

            let priorLength := mload(dst)
            
            mstore(dst, add(priorLength, mload(src)))
        
            // copy    

            pop(
                staticcall(
                  gas(), 4, 
                  add(src, 32), // src data start
                  mload(src), // src length 
                  add(dst, add(32, priorLength)), // dst write ptr
                  mload(dst)
                ) 
            )
        }
    }
}
