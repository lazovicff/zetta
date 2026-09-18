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
    uint256 constant alphax  = 16449029564882376337151460489538288837264354838179119185276458989509593750195;
    uint256 constant alphay  = 14429466103453138548453788594433306030891331933812075194146706407677520169796;
    uint256 constant betax1  = 11743947447429600298271139590007298758283342588188042034608756819401295772011;
    uint256 constant betax2  = 17906698094476253593927899732671597173444664212154365625533359090495025952971;
    uint256 constant betay1  = 261066353963349275659380446825101396864174892483421915765122992092406609413;
    uint256 constant betay2  = 14873368599007444801844785128735542596003100439609805510366848203165774126136;
    uint256 constant gammax1 = 21758408717949456894483509166318277253980105560887113289502571149277686657303;
    uint256 constant gammax2 = 9928214821721470266039936113288144156688251939580107820000505355892200689457;
    uint256 constant gammay1 = 2387646588703145701229539118025675601554541691360773861174232244305423142482;
    uint256 constant gammay2 = 491673724323906113703105167945442979261649477083418649947694171511318347261;
    uint256 constant deltax1 = 17786133608867588062911310890916674875392036740722619177182717865743772651822;
    uint256 constant deltax2 = 17286927157850749116035419112399902623717777629048782653464874937925252624446;
    uint256 constant deltay1 = 7000384006966971729038909053162574598582268002831443747156914318962337967067;
    uint256 constant deltay2 = 1331219889950781640728536793527074268077299577903372131682557651639752865828;

    
    uint256 constant IC0x = 7073142478160021598801046833080258584531089159570515104839671228187821195129;
    uint256 constant IC0y = 18308516336550855368483400488230375563327770973834058690863702803899396843246;
    
    uint256 constant IC1x = 2557185104333987300695576564413016553504698074562123127278589187094074833223;
    uint256 constant IC1y = 10242731968108685389120885603573938469186745794097268255790877085167008047317;
    
    uint256 constant IC2x = 21718461093882739858533537463507475173410473319674362738466396171090398060979;
    uint256 constant IC2y = 5049114365336049620183009501583138236855764191635431983905028612357098075;
    
    uint256 constant IC3x = 19071994815688633407416009108024055434758571002010893254546988121103909246680;
    uint256 constant IC3y = 21571235170092409961019713616224307981944910851130362679086115593370742492431;
    
    uint256 constant IC4x = 15952104185064396066893312420698848408943291007698649418686672508078214623327;
    uint256 constant IC4y = 3411630046182988873599443059278236956132641550664153846623570765409076363095;
    
    uint256 constant IC5x = 5972760737343696335730494797162012525472474938142827367490255288475098379538;
    uint256 constant IC5y = 2424993268425300813435036404862844491706173061454767733218198440305263188371;
    
    uint256 constant IC6x = 1056786200504956609635751626203779926465169123191050679684978466224554425119;
    uint256 constant IC6y = 13844823177895982688383753506928650971062504318556465017186710732257246178899;
    
    
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