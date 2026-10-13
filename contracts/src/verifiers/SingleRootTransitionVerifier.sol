// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;

/*
    Copyright 2021 0KIMS association.

    * `solidity-verifiers` added comment
        This file is a template built out of [snarkJS](https://github.com/iden3/snarkjs) groth16 verifier.
        See the original ejs template [here](https://github.com/iden3/snarkjs/blob/master/templates/verifier_groth16.sol.ejs)
    *

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

contract Groth16Verifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 15364863471096227939792028725555821452022600654984687244557068571195614739716;
    uint256 constant alphay  = 19839563299217608413281757489235881010691156283789493101965302167291058460336;
    uint256 constant betax1  = 4178818820684042322232126618022894131612482716076974117421569522220028095779;
    uint256 constant betax2  = 14315991932274352286769911657794505053287311326839035646962575005618352014281;
    uint256 constant betay1  = 15137142804855176109746803109586190767646686748045494332964915796415763286317;
    uint256 constant betay2  = 5739413524573958194480411786550745283548242464050933767944087769682282780466;
    uint256 constant gammax1 = 5879611820233633620879399578613790320932895166452228883078476983360801468517;
    uint256 constant gammax2 = 10977529475576790064599667760450155115563325759507213013574300261682405736130;
    uint256 constant gammay1 = 6493565098534877721417169605412668242523052603603096741847123020747532811504;
    uint256 constant gammay2 = 6717539768466166525279472620483966123784307851537925099864682132409654550487;
    uint256 constant deltax1 = 1201019305797658355243376425068866602759066238394185299068426310883530792980;
    uint256 constant deltax2 = 4207104298499896615880845861892744725657818748327435758683454252607683954193;
    uint256 constant deltay1 = 10110837582423059673403302956051180669769085927310584126003539571935306441650;
    uint256 constant deltay2 = 18560968140941099540729793918537480974217719736773055673923306227976514513351;

    
    uint256 constant IC0x = 14696111468262321497975380353694194615007737206799289023180022485966296033042;
    uint256 constant IC0y = 12019781930388047965256826710558264055406782663915162707227063047155711378242;
    
    uint256 constant IC1x = 16433892580286242889940709518023712432822356241318121778203202167119726431949;
    uint256 constant IC1y = 18893462973623826501805366368954812100269998238353594638439632288635446794515;
    
    uint256 constant IC2x = 1475037484188209539508922843967054187373727894997802704262721281789141360711;
    uint256 constant IC2y = 21669019888601720014196091590370210514979933941153725087061720526405995434185;
    
    uint256 constant IC3x = 21525237371043155064801488523537084238295367747306070847134551346703920469161;
    uint256 constant IC3y = 5758522847880530092514357584595134512905106837424452168684471932156073525195;
    
    uint256 constant IC4x = 4329449433469040173908089188642064628074352152685102613924203194123855448941;
    uint256 constant IC4y = 1723104423147390851911520909679833557110436932022243683446453234380818486065;
    
    uint256 constant IC5x = 3694720145948994122233063679316339566103889376236906018024508030682439620945;
    uint256 constant IC5y = 12341789209376976031209065749918064869369381410620395886255354918357696333766;
    
    uint256 constant IC6x = 10318872923526868491932127642627137516899603602896537862385900153943678947171;
    uint256 constant IC6y = 2175607085113066215300997890077706330448803086677479220357768686957237829655;
    
    
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[6] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
            
            return(0, 0x20)
        }
    }
}