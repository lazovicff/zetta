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
    uint256 constant alphax  = 9817195825424832970865447295112739831882674345206891603953550472445276091002;
    uint256 constant alphay  = 11052692555130194125604456465857996207618771477238988931924116974208754128785;
    uint256 constant betax1  = 18316523430105999148030792169501085797199968191536488298379732074657254541931;
    uint256 constant betax2  = 13835012381517599650456150936952430290994000165520859982750371261714009441919;
    uint256 constant betay1  = 11119316951644039022161040236876225778981118038250716883093785918351916107090;
    uint256 constant betay2  = 2490198058684530846627632966765348878264949694317310503567876971989762492395;
    uint256 constant gammax1 = 6393249752841885313186862855195358841367811686292661519456556741839372736576;
    uint256 constant gammax2 = 18934482152384011786226846292885085988494252094440965431561769393218091635926;
    uint256 constant gammay1 = 17020558224378418531911940988323543209403588014366165997014831857884625884665;
    uint256 constant gammay2 = 13600613639275868326871820824798660512930583958933745015722203193318609843530;
    uint256 constant deltax1 = 17864339791220915509517730714696391687182302212426815316400373506701447220478;
    uint256 constant deltax2 = 13021019988166251369468723374506361594145718885971379857897011350482272210560;
    uint256 constant deltay1 = 16087911684459669653135330920880327538786950095967660742020089322825520727179;
    uint256 constant deltay2 = 3335274419557703759304382800211320424657521296861933685155730684571220427492;

    
    uint256 constant IC0x = 10558017907162295624349522545016333116981050610499449142606144584828149455051;
    uint256 constant IC0y = 21628569718967866708067176742060860143481117797345000494757650779277470849426;
    
    uint256 constant IC1x = 6335341477942502269869827545181160179310879628902133123628991445232524401368;
    uint256 constant IC1y = 11099568436514408360931406873949640045018505572923286276046856621987362418785;
    
    uint256 constant IC2x = 4596655948571977305476042133092739822006657547389346955361664954490457845330;
    uint256 constant IC2y = 573295686616372251152472519841223891283986367063298917982112852623474121283;
    
    uint256 constant IC3x = 15014909037437246272502786558683987918120349294250577547249706112634091491568;
    uint256 constant IC3y = 11331575584758942105335016475614658561626343374321524105857310559450375723328;
    
    uint256 constant IC4x = 4926243072208719704856362701229198016567607484903053961373846572910282757762;
    uint256 constant IC4y = 16899574799668631285441228006222820720151279876724476978992084215180851794965;
    
    uint256 constant IC5x = 8193977405234550071566291633676184414468774669279828850142891014359788070505;
    uint256 constant IC5y = 14600111100060732563159753070540623990112783626810832166352354346435779580409;
    
    uint256 constant IC6x = 1749820861974597735908570940016558647419349846938292064307789831259375987562;
    uint256 constant IC6y = 18047384832313683574610818676153017783434157042627037432799681606334333082366;
    
    
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