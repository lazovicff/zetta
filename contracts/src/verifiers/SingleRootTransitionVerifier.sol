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
    uint256 constant alphax  = 3550292075376328499003444137019948528409007181323616242645845820251399298382;
    uint256 constant alphay  = 1922452151168752854837977261324409956312864718479814515244223619778776761652;
    uint256 constant betax1  = 18280327556780668278326825588330045729940755536737937338568135482688140947392;
    uint256 constant betax2  = 5315953400743696278042835694516059960728699689907643237162590197876259635515;
    uint256 constant betay1  = 13438013387530334776517169952147605725669918319954567107108423013356027853052;
    uint256 constant betay2  = 10924564110179028884098108909658372189766668514596635507913743800461470021149;
    uint256 constant gammax1 = 4825232035808715797379949077740009351818241304655994746162567759836358086747;
    uint256 constant gammax2 = 5970461771081148889327064977898796832532385317668395176743155155033640565117;
    uint256 constant gammay1 = 4153135655853162144877821535222999459494709156669442083807489750287488899883;
    uint256 constant gammay2 = 14503836341208596287953812914449449171643448637769436107117289931386171067779;
    uint256 constant deltax1 = 203735415142139598665199111818125552444310202393464939754874385764745140109;
    uint256 constant deltax2 = 8743847550457703119541242316712336133517653436005203855750102269719375546017;
    uint256 constant deltay1 = 717481723456871851318427431750293829058069685001692376395974356324006497478;
    uint256 constant deltay2 = 5256139511102017253942348511238207785263805520392041882500712378980647552266;

    
    uint256 constant IC0x = 2144327359073992246368046960196229510499600715897589053054848316224888264361;
    uint256 constant IC0y = 8771753409110830040768277284081189869236680108171119138798215633618897498205;
    
    uint256 constant IC1x = 20694708041982337320817373692163641029412452783611796848985435450897752906380;
    uint256 constant IC1y = 11675866811758099578609461969824221197314962205999952990481251809942519959771;
    
    uint256 constant IC2x = 7587113779825678435164804612790006067683840021036424495081910421254544940490;
    uint256 constant IC2y = 12807451491195001488721487926902731924168755182252863360609861073282497134752;
    
    uint256 constant IC3x = 15007943891577163653411810466808910481593641982093913522056375694389641793989;
    uint256 constant IC3y = 10123036097009146863766134764904477345460523396113915741114081787821755388524;
    
    uint256 constant IC4x = 10632217402041012298264711357801782868392584239944720815542430251285168452389;
    uint256 constant IC4y = 18860546915209831987528351005974381227606528453956641343362717795438287993416;
    
    uint256 constant IC5x = 9583386708564026484307065517863739621205198848848774932236351079085889009063;
    uint256 constant IC5y = 6098665640973693996996171176464010557071534936058834506895520803697688789090;
    
    uint256 constant IC6x = 9347348322461833904365992695535611492168018669524868283320591961268310542493;
    uint256 constant IC6y = 6796792751823394281427286716746191418738324580364673320564820704249866834675;
    
    
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