// SPDX-License-Identifier: GPL-3.0-or-later 
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/BLS12381Helper.sol";

contract BLSHelperTest is Test, BLS12381Helper {

    function setUp() public {
    }

    // ones
    function testG1OneSanity() public {
        uint256 gasBefore = gasleft();
        bytes memory g1One = _g1One;
        console.log("g1One gas used %d", gasBefore-gasleft());
        assertEq(keccak256(g1One) == keccak256(new bytes(128)), false);
    }

    function testG2OneSanity() public {
        uint256 gasBefore = gasleft();
        bytes memory g2One = _g2One;
        console.log("g2One gas used %d", gasBefore-gasleft());
        assertEq(keccak256(g2One) == keccak256(new bytes(256)), false);
    }

    function testG2NegOneSanity() public {
        bytes memory g2NegOne = g2NegOne();
        assertEq(keccak256(g2NegOne) == keccak256(new bytes(256)), false);
    }

    // map
    function testG1MapSanity() public {
        uint256 x; // keep x as 0
        uint256 y = uint256(keccak256("hakuna"));

        uint256 gasBefore = gasleft();
        bytes memory c = _mapToG1(x, y);
        console.log("_mapToG1 gas used %d", gasBefore-gasleft());

        bytes memory zeroStrip = new bytes(128);

        assertEq(keccak256(c) == keccak256(zeroStrip), false);
    }

    function testG1MapSanity(uint256 fuzz) public {
        uint256 x; // keep x as 0
        uint256 y = uint256(keccak256(abi.encodePacked(fuzz)));

        bytes memory c = _mapToG1(x, y);
        bytes memory zeroStrip = new bytes(128);

        assertEq(keccak256(c) == keccak256(zeroStrip), false);
    }

    function testG2MapSanity() public {

        uint256 gasBefore = gasleft();
        bytes memory c = _mapToG2(1, 1, 1, 1);
        console.log("_mapToG2 gas used %d", gasBefore-gasleft());

        bytes memory zeroStrip = new bytes(256);

        assertEq(keccak256(c) == keccak256(zeroStrip), false);
    }

    // mul
    function testG1Mul() public {
        uint256 scalar = uint256(keccak256(abi.encodePacked(uint256(1)))); 

        uint256 gasBefore = gasleft();
        bytes memory c = _g1Mul(g1One(), scalar);
        console.log("_g1Mul gas used %d", gasBefore-gasleft());

        bytes memory zeroStrip = new bytes(128);
        assertEq(keccak256(c) == keccak256(zeroStrip), false);
    }

    function testG1MulFuzz(uint256 fuzzyScalar) public {
        uint256 scalar = fuzzyScalar; 
        if (fuzzyScalar == 0) {
            scalar = uint256(keccak256(abi.encodePacked(fuzzyScalar)));
        }
        bytes memory c = _g1Mul(g1One(), scalar);

        bytes memory zeroStrip = new bytes(128);
        assertEq(keccak256(c) == keccak256(zeroStrip), false);
    }

    function testG2Mul() public {
        uint256 scalar = uint256(keccak256(abi.encodePacked(uint256(1)))); 

        uint256 gasBefore = gasleft();
        bytes memory c = _g2Mul(g2One(), scalar);
        console.log("_g2Mul gas used %d", gasBefore-gasleft());

        bytes memory zeroStrip = new bytes(256);
        assertEq(keccak256(c) == keccak256(zeroStrip), false);
    }

    function testG2MulFuzz(uint256 fuzzyScalar) public {
        uint256 scalar = fuzzyScalar; 
        if (fuzzyScalar == 0) {
            scalar = uint256(keccak256(abi.encodePacked(fuzzyScalar)));
        }
        bytes memory c = _g2Mul(g2One(), scalar);

        bytes memory zeroStrip = new bytes(256);
        assertEq(keccak256(c) == keccak256(zeroStrip), false);
    }

    // mutiexp
    function testG1MultiExp() public {
        uint256 s = uint256(keccak256(abi.encodePacked(uint256(1)))); 
        uint256 t = uint256(keccak256(abi.encodePacked(uint256(2)))); 
        uint256 u = uint256(keccak256(abi.encodePacked(uint256(3)))); 

        uint256 gasBefore = gasleft();
        bytes memory c = _g1Mul(g1One(), s);
        bytes memory d = _g1Mul(g1One(), t);
        bytes memory e = _g1Mul(g1One(), u);
        
        bytes memory sum = _g1Add(c, d);
        sum = _g1Add(sum, e);
        uint256 gasUsedConventional = gasBefore-gasleft();

        bytes memory zeroStrip = new bytes(128);
        assertEq(keccak256(sum) == keccak256(zeroStrip), false);

        bytes memory input = abi.encodePacked(g1One(), s, g1One(), t, g1One(), u);
        gasBefore = gasleft();
        bytes memory multiExp = _g1MultiExp(input);
        uint256 gasUsedMultiExp = gasBefore-gasleft();
        assertEq(keccak256(multiExp) == keccak256(sum), true);

        console.log("g1MultiExp gas comparison: %d conventional %d multiExp", gasUsedConventional, gasUsedMultiExp);
    }

    function testG1MultiExpTrivialBenchmark() public {
        bytes memory c;
        bytes memory d;
        bytes memory e;

        {//stack2deep
        uint256 s = uint256(keccak256(abi.encodePacked(uint256(1)))); 
        uint256 t = uint256(keccak256(abi.encodePacked(uint256(2)))); 
        uint256 u = uint256(keccak256(abi.encodePacked(uint256(3)))); 

        c = _g1Mul(g1One(), s);
        d = _g1Mul(g1One(), t);
        e = _g1Mul(g1One(), u);
        }//stack2deep
        
        uint256 gasBefore = gasleft(); // measure gas here
        bytes memory sum = _g1Add(c, d);
        sum = _g1Add(sum, e);
        uint256 gasUsedConventional = gasBefore-gasleft();

        bytes memory zeroStrip = new bytes(128);
        assertEq(keccak256(sum) == keccak256(zeroStrip), false);

        uint256 one = 1;
        bytes memory input = abi.encodePacked(c, one, d, one, e, one);
        gasBefore = gasleft();
        bytes memory multiExp = _g1MultiExp(input);
        uint256 gasUsedMultiExp = gasBefore-gasleft();
        assertEq(keccak256(multiExp) == keccak256(sum), true);

        console.log("g1MultiExpTrivialSum gas comparison: %d conventional %d multiExp", gasUsedConventional, gasUsedMultiExp);
    }

    function testG1MultiExpFuzz(uint256 x, uint256 y, uint256 z) public {
        uint256 s = x;
        uint256 t = y;
        uint256 u = z;

        uint256 gasBefore = gasleft();
        bytes memory c = _g1Mul(g1One(), s);
        bytes memory d = _g1Mul(g1One(), t);
        bytes memory e = _g1Mul(g1One(), u);
        
        bytes memory sum = _g1Add(c, d);
        sum = _g1Add(sum, e);
        uint256 gasUsedConventional = gasBefore-gasleft();

        bytes memory zeroStrip = new bytes(128);
        if (!(x == 0 && y == 0 && z == 0)) {
          assertEq(keccak256(sum) == keccak256(zeroStrip), false);
        } else {
          assertEq(keccak256(sum) == keccak256(zeroStrip), true);
        }

        bytes memory input = abi.encodePacked(g1One(), s, g1One(), t, g1One(), u);
        gasBefore = gasleft();
        bytes memory multiExp = _g1MultiExp(input);
        uint256 gasUsedMultiExp = gasBefore-gasleft();
        assertEq(keccak256(multiExp) == keccak256(sum), true);

        console.log("g1MultiExp gas comparison: %d conventional %d multiExp", gasUsedConventional, gasUsedMultiExp);
    }

    function testG2MultiExp() public {
        uint256 s = uint256(keccak256(abi.encodePacked(uint256(1)))); 
        uint256 t = uint256(keccak256(abi.encodePacked(uint256(2)))); 
        uint256 u = uint256(keccak256(abi.encodePacked(uint256(3)))); 

        uint256 gasBefore = gasleft();
        bytes memory c = _g2Mul(g2One(), s);
        bytes memory d = _g2Mul(g2One(), t);
        bytes memory e = _g2Mul(g2One(), u);
        
        bytes memory sum = _g2Add(c, d);
        sum = _g2Add(sum, e);
        uint256 gasUsedConventional = gasBefore-gasleft();

        bytes memory zeroStrip = new bytes(256);
        assertEq(keccak256(sum) == keccak256(zeroStrip), false);

        bytes memory input = abi.encodePacked(g2One(), s, g2One(), t, g2One(), u);
        gasBefore = gasleft();
        bytes memory multiExp = _g2MultiExp(input);
        uint256 gasUsedMultiExp = gasBefore-gasleft();
        assertEq(keccak256(multiExp) == keccak256(sum), true);

        console.log("g2MultiExp gas comparison: %d conventional %d multiExp", gasUsedConventional, gasUsedMultiExp);
    }

    function testG2MultiExpFuzz(uint256 x, uint256 y, uint256 z) public {
        uint256 s = x;
        uint256 t = y;
        uint256 u = z;

        uint256 gasBefore = gasleft();
        bytes memory c = _g2Mul(g2One(), s);
        bytes memory d = _g2Mul(g2One(), t);
        bytes memory e = _g2Mul(g2One(), u);
        
        bytes memory sum = _g2Add(c, d);
        sum = _g2Add(sum, e);
        uint256 gasUsedConventional = gasBefore-gasleft();

        bytes memory zeroStrip = new bytes(256);
        if (!(x == 0 && y == 0 && z == 0)) {
          assertEq(keccak256(sum) == keccak256(zeroStrip), false);
        } else {
          assertEq(keccak256(sum) == keccak256(zeroStrip), true);
        } 

        bytes memory input = abi.encodePacked(g2One(), s, g2One(), t, g2One(), u);
        gasBefore = gasleft();
        bytes memory multiExp = _g2MultiExp(input);
        uint256 gasUsedMultiExp = gasBefore-gasleft();
        assertEq(keccak256(multiExp) == keccak256(sum), true);

        console.log("g2MultiExp gas comparison: %d conventional %d multiExp", gasUsedConventional, gasUsedMultiExp);
    }

    // add
    function testG1Add() public {
        uint256 x = uint256(keccak256(abi.encodePacked(uint256(0)))); 
        uint256 y = uint256(keccak256(abi.encodePacked(uint256(1)))); 
      
        bytes memory xc = _g1Mul(g1One(), x);
        bytes memory yc = _g1Mul(g1One(), y);

        uint256 gasBefore = gasleft();
        bytes memory c = _g1Add(xc, yc);
        console.log("_g1Add gas used %d", gasBefore-gasleft());

        bytes memory zeroStrip = new bytes(128);
        assertEq(keccak256(c) == keccak256(zeroStrip), false);

        bytes memory cc = _g1Add(yc, xc);
        assertEq(keccak256(c) == keccak256(cc), true);

        cc = _g1Mul(g1One(), x+y); // careful as uint256 space is smaller than the modulus of the ground field, so only works for some "small" x,y
        assertEq(keccak256(c) == keccak256(cc), true);
    }

    function testG1AddFuzz(uint256 x, uint256 y) public {
        x = (x == 0) ? uint256(keccak256(abi.encodePacked(x))) : x; 
        y = (y == 0) ? uint256(keccak256(abi.encodePacked(y))) : y; 
      
        bytes memory xc = _g1Mul(g1One(), x);
        bytes memory yc = _g1Mul(g1One(), y);

        bytes memory c = _g1Add(xc, yc);

        bytes memory zeroStrip = new bytes(128);
        assertEq(keccak256(c) == keccak256(zeroStrip), false);

        bytes memory cc = _g1Add(yc, xc);
        assertEq(keccak256(c) == keccak256(cc), true);

        //cc = _g1Mul(g1One(), x+y); // fails, arithmetic overflow, and otherwise wouldn't respect modulus of ground field
        //assertEq(keccak256(c) == keccak256(cc), true);
    }

    function testG1Add_Double() public {
        uint256 x = uint256(keccak256(abi.encodePacked("rando"))); 
      
        bytes memory xc = _g1Mul(g1One(), x);

        bytes memory c = _g1Add(xc, xc);

        bytes memory zeroStrip = new bytes(128);
        assertEq(keccak256(c) == keccak256(zeroStrip), false);

        bytes memory _2xc = _g1Mul(xc, 2);
        assertEq(keccak256(c) == keccak256(_2xc), true);
    }

    function testG1Add_DoubleFuzz(uint256 x) public {
        x = (x == 0) ? uint256(keccak256(abi.encodePacked(x))) : x; 

        bytes memory xc = _g1Mul(g1One(), x);

        bytes memory c = _g1Add(xc, xc);

        bytes memory zeroStrip = new bytes(128);
        assertEq(keccak256(c) == keccak256(zeroStrip), false);

        bytes memory _2xc = _g1Mul(xc, 2);
        assertEq(keccak256(c) == keccak256(_2xc), true);
    }

    function testG2Add() public {
        uint256 x = uint256(keccak256(abi.encodePacked(uint256(0)))); 
        uint256 y = uint256(keccak256(abi.encodePacked(uint256(1)))); 
      
        bytes memory xc = _g2Mul(g2One(), x);
        bytes memory yc = _g2Mul(g2One(), y);

        uint256 gasBefore = gasleft();
        bytes memory c = _g2Add(xc, yc);
        console.log("_g2Add gas used %d", gasBefore-gasleft());

        bytes memory zeroStrip = new bytes(256);
        assertEq(keccak256(c) == keccak256(zeroStrip), false);

        bytes memory cc = _g2Add(yc, xc);
        assertEq(keccak256(c) == keccak256(cc), true);
    }
    
    function testG2AddFuzz(uint256 x, uint256 y) public {
        x = (x == 0) ? uint256(keccak256(abi.encodePacked(x))) : x; 
        y = (y == 0) ? uint256(keccak256(abi.encodePacked(y))) : y; 
      
        bytes memory xc = _g2Mul(g2One(), x);
        bytes memory yc = _g2Mul(g2One(), y);

        bytes memory c = _g2Add(xc, yc);

        bytes memory zeroStrip = new bytes(256);
        assertEq(keccak256(c) == keccak256(zeroStrip), false);

        bytes memory cc = _g2Add(yc, xc);
        assertEq(keccak256(c) == keccak256(cc), true);
    }

    function testG2Add_Double() public {
        uint256 x = uint256(keccak256(abi.encodePacked("rando"))); 
      
        bytes memory xc = _g2Mul(g2One(), x);

        bytes memory c = _g2Add(xc, xc);

        bytes memory zeroStrip = new bytes(256);
        assertEq(keccak256(c) == keccak256(zeroStrip), false);

        bytes memory _2xc = _g2Mul(xc, 2);
        assertEq(keccak256(c) == keccak256(_2xc), true);
    }

    function testG2Add_DoubleFuzz(uint256 x) public {
        x = (x == 0) ? uint256(keccak256(abi.encodePacked(x))) : x; 

        bytes memory xc = _g2Mul(g2One(), x);

        bytes memory c = _g2Add(xc, xc);

        bytes memory zeroStrip = new bytes(256);
        assertEq(keccak256(c) == keccak256(zeroStrip), false);

        bytes memory _2xc = _g2Mul(xc, 2);
        assertEq(keccak256(c) == keccak256(_2xc), true);
    }

    function testPairingSanity() public {
        bytes memory g1One = g1One();
        bytes memory g2One = g2One(); 
        bytes memory g2NegOne = g2NegOne();

        bytes memory input = abi.encodePacked(g1One, g2One, g1One, g2NegOne);

        uint256 gasBefore = gasleft();
        bool result = _checkPairing(input);
        console.log("_checkPairing gas used %d", gasBefore-gasleft());

        assertEq(result, true);
    }

    function testSignatureSanity() public {
        uint256 dummySecretKey = uint256(keccak256("dummySecretKey"));
        bytes memory pk2 = _g2Mul(g2NegOne(), dummySecretKey);

        bytes32[6] memory messageDigests;
        messageDigests[0] = keccak256("what");
        messageDigests[1] = keccak256("is");
        messageDigests[2] = keccak256("the");
        messageDigests[3] = keccak256("meaning");
        messageDigests[4] = keccak256("of");
        messageDigests[5] = keccak256("life?");

        bytes memory sumHash1 = _g1Mul(g1One(), 0);
        bytes memory h1;
        for (uint256 i; i < messageDigests.length; ++i) {
            h1 = _mapToG1(0, uint256(messageDigests[i])); // in practice this "hash" should have eip 712 safeguards 
            sumHash1 = _g1Add(sumHash1, h1);
        }

        bytes memory aggregateSignature1 = _g1Mul(g1One(), 0);
        bytes memory sig1;
        for (uint256 i; i < messageDigests.length; ++i) {
            h1 = _mapToG1(0, uint256(messageDigests[i])); // in practice this "hash" should have eip 712 safeguards 
            sig1 = _g1Mul(h1, dummySecretKey);
            aggregateSignature1 = _g1Add(aggregateSignature1, sig1); 
        }

        // check e(aggSig1, G2) == e(sum(h_i), pk2)
        bytes memory input = abi.encodePacked(aggregateSignature1, g2One(), sumHash1, pk2);

        bool result = _checkPairing(input);

        assertEq(result, true);
    }
}
