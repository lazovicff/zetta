// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;

/*
    Sonobe's Nova + CycleFold decider verifier.
    Joint effort by 0xPARC & PSE.

    More details at https://github.com/privacy-scaling-explorations/sonobe
    Usage and design documentation at https://privacy-scaling-explorations.github.io/sonobe-docs/

    Uses the https://github.com/iden3/snarkjs/blob/master/templates/verifier_groth16.sol.ejs
    Groth16 verifier implementation and a KZG10 Solidity template adapted from
    https://github.com/weijiekoh/libkzg.
    Additionally we implement the NovaDecider contract, which combines the
    Groth16 and KZG10 verifiers to verify the zkSNARK proofs coming from
    Nova+CycleFold folding.
*/


/* =============================== */
/* KZG10 verifier methods */
/**
 * @author  Privacy and Scaling Explorations team - pse.dev
 * @dev     Contains utility functions for ops in BN254; in G_1 mostly.
 * @notice  Forked from https://github.com/weijiekoh/libkzg.
 * Among others, a few of the changes we did on this fork were:
 * - Templating the pragma version
 * - Removing type wrappers and use uints instead
 * - Performing changes on arg types
 * - Update some of the `require` statements 
 * - Use the bn254 scalar field instead of checking for overflow on the babyjub prime
 * - In batch checking, we compute auxiliary polynomials and their commitments at the same time.
 */
contract KZG10Verifier {

    // prime of field F_p over which y^2 = x^3 + 3 is defined
    uint256 public constant BN254_PRIME_FIELD =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 public constant BN254_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /**
     * @notice  Performs scalar multiplication in G_1.
     * @param   p  G_1 point to multiply
     * @param   s  Scalar to multiply by
     * @return  r  G_1 point p multiplied by scalar s
     */
    function mulScalar(uint256[2] memory p, uint256 s) internal view returns (uint256[2] memory r) {
        uint256[3] memory input;
        input[0] = p[0];
        input[1] = p[1];
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x60, r, 0x40)
            switch success
            case 0 { invalid() }
        }
        require(success, "bn254: scalar mul failed");
    }

    /**
     * @notice  Negates a point in G_1.
     * @param   p  G_1 point to negate
     * @return  uint256[2]  G_1 point -p
     */
    function negate(uint256[2] memory p) internal pure returns (uint256[2] memory) {
        if (p[0] == 0 && p[1] == 0) {
            return p;
        }
        return [p[0], BN254_PRIME_FIELD - (p[1] % BN254_PRIME_FIELD)];
    }

    /**
     * @notice  Adds two points in G_1.
     * @param   p1  G_1 point 1
     * @param   p2  G_1 point 2
     * @return  r  G_1 point p1 + p2
     */
    function add(uint256[2] memory p1, uint256[2] memory p2) internal view returns (uint256[2] memory r) {
        bool success;
        uint256[4] memory input = [p1[0], p1[1], p2[0], p2[1]];
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0x80, r, 0x40)
            switch success
            case 0 { invalid() }
        }

        require(success, "bn254: point add failed");
    }

    /**
     * @notice  Computes the pairing check e(p1, p2) * e(p3, p4) == 1
     * @dev     Note that G_2 points a*i + b are encoded as two elements of F_p, (a, b)
     * @param   a_1  G_1 point 1
     * @param   a_2  G_2 point 1
     * @param   b_1  G_1 point 2
     * @param   b_2  G_2 point 2
     * @return  result  true if pairing check is successful
     */
    function pairing(uint256[2] memory a_1, uint256[2][2] memory a_2, uint256[2] memory b_1, uint256[2][2] memory b_2)
        internal
        view
        returns (bool result)
    {
        uint256[12] memory input = [
            a_1[0],
            a_1[1],
            a_2[0][1], // imaginary part first
            a_2[0][0],
            a_2[1][1], // imaginary part first
            a_2[1][0],
            b_1[0],
            b_1[1],
            b_2[0][1], // imaginary part first
            b_2[0][0],
            b_2[1][1], // imaginary part first
            b_2[1][0]
        ];

        uint256[1] memory out;
        bool success;

        assembly {
            success := staticcall(sub(gas(), 2000), 8, input, 0x180, out, 0x20)
            switch success
            case 0 { invalid() }
        }

        require(success, "bn254: pairing failed");

        return out[0] == 1;
    }

    uint256[2] G_1 = [
            17628143147024637660932984872616734421513956857586751006348310521752537292924,
            15373706931498437926953704894529672396533715702461957241833346662226072416060
    ];
    uint256[2][2] G_2 = [
        [
            13059409087030499873054603567072548643484755475717775171583667147744303150110,
            2358952747559609859838159550969046824583647683359353966240304518565944144415
        ],
        [
            1043628208896499505497625694210530577436880937653770349508278935249681923295,
            18803200453706305108860373007309629523885355817822835545148475740814423587738
        ]
    ];
    uint256[2][2] VK = [
        [
            13755429210707728300045761145361174482036038539295142751921321024240211648791,
            17439578327540494849862916052476752111376539433639733448067358505741662281956
        ],
        [
            7904665157152619131019909230201525876577552306413550634870645820694713494513,
            10076872130813532965431588616328359225837934936842426165317603446849130380567
        ]
    ];

    

    /**
     * @notice  Verifies a single point evaluation proof. Function name follows `ark-poly`.
     * @dev     To avoid ops in G_2, we slightly tweak how the verification is done.
     * @param   c  G_1 point commitment to polynomial.
     * @param   pi G_1 point proof.
     * @param   x  Value to prove evaluation of polynomial at.
     * @param   y  Evaluation poly(x).
     * @return  result Indicates if KZG proof is correct.
     */
    function check(uint256[2] calldata c, uint256[2] calldata pi, uint256 x, uint256 y)
        public
        view
        returns (bool result)
    {
        //
        // we want to:
        //      1. avoid gas intensive ops in G2
        //      2. format the pairing check in line with what the evm opcode expects.
        //
        // we can do this by tweaking the KZG check to be:
        //
        //          e(pi, vk - x * g2) = e(c - y * g1, g2) [initial check]
        //          e(pi, vk - x * g2) * e(c - y * g1, g2)^{-1} = 1
        //          e(pi, vk - x * g2) * e(-c + y * g1, g2) = 1 [bilinearity of pairing for all subsequent steps]
        //          e(pi, vk) * e(pi, -x * g2) * e(-c + y * g1, g2) = 1
        //          e(pi, vk) * e(-x * pi, g2) * e(-c + y * g1, g2) = 1
        //          e(pi, vk) * e(x * -pi - c + y * g1, g2) = 1 [done]
        //                        |_   rhs_pairing  _|
        //
        uint256[2] memory rhs_pairing =
            add(mulScalar(negate(pi), x), add(negate(c), mulScalar(G_1, y)));
        return pairing(pi, VK, rhs_pairing, G_2);
    }

    function evalPolyAt(uint256[] memory _coefficients, uint256 _index) public pure returns (uint256) {
        uint256 m = BN254_SCALAR_FIELD;
        uint256 result = 0;
        uint256 powerOfX = 1;

        for (uint256 i = 0; i < _coefficients.length; i++) {
            uint256 coeff = _coefficients[i];
            assembly {
                result := addmod(result, mulmod(powerOfX, coeff, m), m)
                powerOfX := mulmod(powerOfX, _index, m)
            }
        }
        return result;
    }

    
}

/* =============================== */
/* Groth16 verifier methods */
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
    uint256 constant alphax  = 3084178720227970729678704721147609027977024929090892131450938291859876790082;
    uint256 constant alphay  = 1867249924256487245574629736568923296437405175645632048597519206137681273829;
    uint256 constant betax1  = 12568582455367451684705179235831629358733388032211644973593023160214300070703;
    uint256 constant betax2  = 17752315966120587744550177623371328804851668756816539179950625851036710252271;
    uint256 constant betay1  = 5069354067217487793840939604984643493529367334717829848227500381582965451872;
    uint256 constant betay2  = 9445818364797362749363638029566832912511671291546102340863581342177089262074;
    uint256 constant gammax1 = 2454605492751282003744746025889782137730206656515470933309528942129298881399;
    uint256 constant gammax2 = 12614086192226521810366668403697115099545761171480178982110444387515172001301;
    uint256 constant gammay1 = 13112373447860067987663568075480774006446225617186198056862344347056846907607;
    uint256 constant gammay2 = 15775309341535154644507333913394877832531594693819507251926203379023195512727;
    uint256 constant deltax1 = 4860501858787125236147551911874141116535314139151223338823819825304099060719;
    uint256 constant deltax2 = 3450627772600504153612782075640298361443769803573889029145469240362890606630;
    uint256 constant deltay1 = 7906983523180195455334672313554941845956180696240044612121800413423632581140;
    uint256 constant deltay2 = 2300964736526417453786956433519399648977604793895220763943668412649731257728;

    
    uint256 constant IC0x = 18131618848340025915359917058768272765415739805271520016536827767589950459427;
    uint256 constant IC0y = 14245998851439574594182426241468865150868495303850149156303402919349273091645;
    
    uint256 constant IC1x = 8638119557040426732158532803948613985224321898598721760126002522506073882112;
    uint256 constant IC1y = 9746585465874752292477030396090221464855958633103065432235484580700001298259;
    
    uint256 constant IC2x = 18416940184762585546288152208129134999513564016669214327944677379913354418354;
    uint256 constant IC2y = 14492186360267804819545056698691681692397391131397312798112864200485687418748;
    
    uint256 constant IC3x = 14478999672565944362285104158398242997118310811761754486596908304707057439094;
    uint256 constant IC3y = 1126978708497408715586222610354932957003010548698813312659812378637764476728;
    
    uint256 constant IC4x = 14800678289884888094534714469460352536250969024324399599336391997784566851551;
    uint256 constant IC4y = 3557316626662120397088312743173437734673632779006694797835473943083828355860;
    
    uint256 constant IC5x = 11805806796169435899119942108866885076614243363081563911877718056593173765915;
    uint256 constant IC5y = 18983335206519195999439833103371740734539613978965149903000675081063869528332;
    
    uint256 constant IC6x = 15661840406323880464931717071568904161718344728739430040134988006378301332422;
    uint256 constant IC6y = 20301570238721377232329962801020488639711928971668935493021635240636188039424;
    
    uint256 constant IC7x = 6545187692750392255701752310024186927030104309692141801474613708603684351284;
    uint256 constant IC7y = 13263541775566120498806226604300651088819618960310024094484629084146319505766;
    
    uint256 constant IC8x = 17395824489949649620080586673978380091157029925162609955071394434320227951068;
    uint256 constant IC8y = 5122482414151734160261362079600249441727651643314060316209983365082389077814;
    
    uint256 constant IC9x = 13468356247183032805978580094544005273085933238184837354989696948372230663261;
    uint256 constant IC9y = 11134121701153789268019473198983353801694072348186397930908543532421585022713;
    
    uint256 constant IC10x = 9166118767534249164207226281330788605079654120425485756893581841257557100492;
    uint256 constant IC10y = 17657741045274072505936368333011971839909028115703806946551342682524350197152;
    
    uint256 constant IC11x = 6220986688767395424567017730888426142690620878179748595645896874799074924781;
    uint256 constant IC11y = 1774905921070171423505736014428952913375434696461914975511879520899445400263;
    
    uint256 constant IC12x = 5006097251303411156182392262928664001292223484868847959598141181685365798841;
    uint256 constant IC12y = 15686080956630127860978255558332310112302067091632065005252353515169246519442;
    
    uint256 constant IC13x = 12463613410855095953555363248497819303043839798516522757007905315657852848707;
    uint256 constant IC13y = 7601508651115007211765650334338852098074546864814838165929916627265070800860;
    
    uint256 constant IC14x = 6989298049992604756661492365088462675304943911218917452419758189515176059926;
    uint256 constant IC14y = 5885495410514556933558444682767238328960259380084481010772450503384513378154;
    
    uint256 constant IC15x = 2024787511593596735208602763188510786001254858521652154989270942651580920409;
    uint256 constant IC15y = 176483387352061858240995937784752284439442747036291128109764755015864766731;
    
    uint256 constant IC16x = 11100643931193091768134838245224985717764043863984527242847190766281849099517;
    uint256 constant IC16y = 3915902578253562489739299651916094220220836219281213983931229454811119462532;
    
    uint256 constant IC17x = 21500459651844160676398762782738730819836737947186543994355540983477602393025;
    uint256 constant IC17y = 17199330662258746916527659484436486841547888702451638011769653982125307388610;
    
    uint256 constant IC18x = 12358369626266366943991250746360045209540005875825462445537410683111730513513;
    uint256 constant IC18y = 15769043209709915716843968895928339664472452679468719634383335044255028815520;
    
    uint256 constant IC19x = 12360217612521955780150402913723800830529511558039968440025384966576835534601;
    uint256 constant IC19y = 11191465022129791852692940827720683984725439799998212295338526765405835416463;
    
    uint256 constant IC20x = 1651710665952635609588738055526738396852051878595079059272712284283150919285;
    uint256 constant IC20y = 3134907790716621339775001799171266589646072708110840856141593270012532915951;
    
    uint256 constant IC21x = 7469689471616181691324360880136077516951182118823759226340296940616426331463;
    uint256 constant IC21y = 3978261913302470298878605712015220147699682591925172178203554839826850331507;
    
    uint256 constant IC22x = 16175005883840212282662189107103444619097089589234210355849310634955752941;
    uint256 constant IC22y = 586128377449184677141162454003303444575093730337844241649529428060813800022;
    
    uint256 constant IC23x = 16943113129384379465563361845169598847895334063694702997547210461475010726358;
    uint256 constant IC23y = 9786243975107747637475184085573177264073954460121152481418950659072651471011;
    
    uint256 constant IC24x = 11148796984438975878102191833325684704359315365160808906521336091080548511672;
    uint256 constant IC24y = 11159112605363233665593290803611945694760573632393384389195745221877592871142;
    
    uint256 constant IC25x = 19211298252211351541504343103414731168679075439988229031007307532857463465847;
    uint256 constant IC25y = 19007976370486618325737412872400665884148169159135255883802067553325055300755;
    
    uint256 constant IC26x = 19096903946352341921276192241137943975789140705411506954611237675826566936569;
    uint256 constant IC26y = 2757011352286192631271454982702510153212870106485755990985184324067540392072;
    
    uint256 constant IC27x = 13520515260232952048043738047762929544845962443094132774848473001667042801266;
    uint256 constant IC27y = 1310707604797379748657511237221058403037249633875480211449364919017380248323;
    
    uint256 constant IC28x = 8105376678474148872687195939042221582457994852486657274791039238000151444618;
    uint256 constant IC28y = 4354937167873893299288319845246796860660759806803910018240444231283523332729;
    
    uint256 constant IC29x = 2572466245329342521313856231719117951633120398208921611132180242718725572124;
    uint256 constant IC29y = 12446726610353719065432867878827826827585184423299875689694674520354837918841;
    
    uint256 constant IC30x = 15454686306267660274088644944690275773446837823736780773035223707003363648599;
    uint256 constant IC30y = 20554878400261062917953130127403936482627510687134982458422685371112622644267;
    
    uint256 constant IC31x = 15703544099487807694645232058249835095189301406098457666144380241527622885183;
    uint256 constant IC31y = 18577496831354420094881739775566729925890715900307424504381826157546461670745;
    
    uint256 constant IC32x = 11651581710486210697281425680071626441665015301661890204257799350119856898228;
    uint256 constant IC32y = 11452633064549005224862278520944133585279037704116679309164303604089547627644;
    
    uint256 constant IC33x = 8676970760716680432716962588326709180488215703320534126860793567350575757414;
    uint256 constant IC33y = 4233126423016718631931161550491245642448430904042555826267289574538156644148;
    
    uint256 constant IC34x = 8344255601921506836048903965058633425384110876666089041003780527815486480687;
    uint256 constant IC34y = 21514345893160133752492256928914725282484903810847347648770804915822198443235;
    
    uint256 constant IC35x = 6481068692203409650808496618259769340457185109317411320908912285977844257405;
    uint256 constant IC35y = 12726039669400157159338020782542648322217301852335822117881003684586074292048;
    
    uint256 constant IC36x = 16359897814230954296155414867518714522938305320595203721320347983322942924986;
    uint256 constant IC36y = 16547742199284524809441594661849344345628779676868064860093489434947844177733;
    
    uint256 constant IC37x = 16893606698097457428693401973833364840060557157060865201435577061191403142591;
    uint256 constant IC37y = 12673377383782534366799438870565165508284672714038432965350958849134863471746;
    
    uint256 constant IC38x = 1086169791894071773018057389696689844254751996059122315605574631808670851847;
    uint256 constant IC38y = 6849912392457200114769259059352575936836622362114381368665912857204121357059;
    
    uint256 constant IC39x = 18079571390561296316957166990816732000792375638486824146753360798313366656651;
    uint256 constant IC39y = 21820190878480776487411524778382651910655012566728512320525507867517683642296;
    
    uint256 constant IC40x = 4152980705607658092515771306521243059927207092039475163958781769541350755588;
    uint256 constant IC40y = 1931584311751970686119415542626856213288166748836055891468444778811305224189;
    
    uint256 constant IC41x = 17479284928437358800050458284240022191585077774962866300279442953654385767379;
    uint256 constant IC41y = 14031471181013049475254665389050019618270976756837472507862010353712345795273;
    
    uint256 constant IC42x = 7628912592858554640650182790444393784837043961186902821904460088475402367255;
    uint256 constant IC42y = 1788091862202034445328512537534546808753196096185011564096897563236782028722;
    
    uint256 constant IC43x = 668828865141918688277939983224085200282279933563130488724554432102607580336;
    uint256 constant IC43y = 16522338818938014379221724606443506003133238916584282038725277841697861198199;
    
    uint256 constant IC44x = 1683160656331448013154216752757923436977590275995448475331183035111182193631;
    uint256 constant IC44y = 2061603041440176394504184106058272601300740183933578383255618388990227799960;
    
    
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[44] calldata _pubSignals) public view returns (bool) {
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
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))
                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))
                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))
                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))
                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))
                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))
                g1_mulAccC(_pVk, IC17x, IC17y, calldataload(add(pubSignals, 512)))
                g1_mulAccC(_pVk, IC18x, IC18y, calldataload(add(pubSignals, 544)))
                g1_mulAccC(_pVk, IC19x, IC19y, calldataload(add(pubSignals, 576)))
                g1_mulAccC(_pVk, IC20x, IC20y, calldataload(add(pubSignals, 608)))
                g1_mulAccC(_pVk, IC21x, IC21y, calldataload(add(pubSignals, 640)))
                g1_mulAccC(_pVk, IC22x, IC22y, calldataload(add(pubSignals, 672)))
                g1_mulAccC(_pVk, IC23x, IC23y, calldataload(add(pubSignals, 704)))
                g1_mulAccC(_pVk, IC24x, IC24y, calldataload(add(pubSignals, 736)))
                g1_mulAccC(_pVk, IC25x, IC25y, calldataload(add(pubSignals, 768)))
                g1_mulAccC(_pVk, IC26x, IC26y, calldataload(add(pubSignals, 800)))
                g1_mulAccC(_pVk, IC27x, IC27y, calldataload(add(pubSignals, 832)))
                g1_mulAccC(_pVk, IC28x, IC28y, calldataload(add(pubSignals, 864)))
                g1_mulAccC(_pVk, IC29x, IC29y, calldataload(add(pubSignals, 896)))
                g1_mulAccC(_pVk, IC30x, IC30y, calldataload(add(pubSignals, 928)))
                g1_mulAccC(_pVk, IC31x, IC31y, calldataload(add(pubSignals, 960)))
                g1_mulAccC(_pVk, IC32x, IC32y, calldataload(add(pubSignals, 992)))
                g1_mulAccC(_pVk, IC33x, IC33y, calldataload(add(pubSignals, 1024)))
                g1_mulAccC(_pVk, IC34x, IC34y, calldataload(add(pubSignals, 1056)))
                g1_mulAccC(_pVk, IC35x, IC35y, calldataload(add(pubSignals, 1088)))
                g1_mulAccC(_pVk, IC36x, IC36y, calldataload(add(pubSignals, 1120)))
                g1_mulAccC(_pVk, IC37x, IC37y, calldataload(add(pubSignals, 1152)))
                g1_mulAccC(_pVk, IC38x, IC38y, calldataload(add(pubSignals, 1184)))
                g1_mulAccC(_pVk, IC39x, IC39y, calldataload(add(pubSignals, 1216)))
                g1_mulAccC(_pVk, IC40x, IC40y, calldataload(add(pubSignals, 1248)))
                g1_mulAccC(_pVk, IC41x, IC41y, calldataload(add(pubSignals, 1280)))
                g1_mulAccC(_pVk, IC42x, IC42y, calldataload(add(pubSignals, 1312)))
                g1_mulAccC(_pVk, IC43x, IC43y, calldataload(add(pubSignals, 1344)))
                g1_mulAccC(_pVk, IC44x, IC44y, calldataload(add(pubSignals, 1376)))

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
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            
            checkField(calldataload(add(_pubSignals, 288)))
            
            checkField(calldataload(add(_pubSignals, 320)))
            
            checkField(calldataload(add(_pubSignals, 352)))
            
            checkField(calldataload(add(_pubSignals, 384)))
            
            checkField(calldataload(add(_pubSignals, 416)))
            
            checkField(calldataload(add(_pubSignals, 448)))
            
            checkField(calldataload(add(_pubSignals, 480)))
            
            checkField(calldataload(add(_pubSignals, 512)))
            
            checkField(calldataload(add(_pubSignals, 544)))
            
            checkField(calldataload(add(_pubSignals, 576)))
            
            checkField(calldataload(add(_pubSignals, 608)))
            
            checkField(calldataload(add(_pubSignals, 640)))
            
            checkField(calldataload(add(_pubSignals, 672)))
            
            checkField(calldataload(add(_pubSignals, 704)))
            
            checkField(calldataload(add(_pubSignals, 736)))
            
            checkField(calldataload(add(_pubSignals, 768)))
            
            checkField(calldataload(add(_pubSignals, 800)))
            
            checkField(calldataload(add(_pubSignals, 832)))
            
            checkField(calldataload(add(_pubSignals, 864)))
            
            checkField(calldataload(add(_pubSignals, 896)))
            
            checkField(calldataload(add(_pubSignals, 928)))
            
            checkField(calldataload(add(_pubSignals, 960)))
            
            checkField(calldataload(add(_pubSignals, 992)))
            
            checkField(calldataload(add(_pubSignals, 1024)))
            
            checkField(calldataload(add(_pubSignals, 1056)))
            
            checkField(calldataload(add(_pubSignals, 1088)))
            
            checkField(calldataload(add(_pubSignals, 1120)))
            
            checkField(calldataload(add(_pubSignals, 1152)))
            
            checkField(calldataload(add(_pubSignals, 1184)))
            
            checkField(calldataload(add(_pubSignals, 1216)))
            
            checkField(calldataload(add(_pubSignals, 1248)))
            
            checkField(calldataload(add(_pubSignals, 1280)))
            
            checkField(calldataload(add(_pubSignals, 1312)))
            
            checkField(calldataload(add(_pubSignals, 1344)))
            
            checkField(calldataload(add(_pubSignals, 1376)))
            
            checkField(calldataload(add(_pubSignals, 1408)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
            
            return(0, 0x20)
        }
    }
}


/* =============================== */
/* Nova+CycleFold Decider verifier */
/**
 * @notice  Computes the decomposition of a `uint256` into num_limbs limbs of bits_per_limb bits each.
 * @dev     Compatible with sonobe::folding-schemes::folding::circuits::nonnative::nonnative_field_to_field_elements.
 */
library LimbsDecomposition {
    function decompose(uint256 x) internal pure returns (uint256[5] memory) {
        uint256[5] memory limbs;
        for (uint8 i = 0; i < 5; i++) {
            limbs[i] = (x >> (55 * i)) & ((1 << 55) - 1);
        }
        return limbs;
    }
}

/**
 * @author PSE & 0xPARC
 * @title  Interface for the NovaDecider contract hiding proof details.
 * @dev    This interface enables calling the verifyNovaProof function without exposing the proof details.
 */
interface OpaqueDecider {
    /**
     * @notice  Verifies a Nova+CycleFold proof given initial and final IVC states, number of steps and the rest proof inputs concatenated.
     * @dev     This function should simply reorganize arguments and pass them to the proper verification function.
     */
    function verifyOpaqueNovaProofWithInputs(
        uint256 steps, // number of folded steps (i)
        uint256[4] calldata initial_state, // initial IVC state (z0)
        uint256[4] calldata final_state, // IVC state after i steps (zi)
        uint256[25] calldata proof // the rest of the decider inputs
    ) external view returns (bool);

    /**
     * @notice  Verifies a Nova+CycleFold proof given all the proof inputs collected in a single array.
     * @dev     This function should simply reorganize arguments and pass them to the proper verification function.
     */
    function verifyOpaqueNovaProof(uint256[34] calldata proof) external view returns (bool);
}

/**
 * @author  PSE & 0xPARC
 * @title   NovaDecider contract, for verifying Nova IVC SNARK proofs.
 * @dev     This is an askama template which, when templated, features a Groth16 and KZG10 verifiers from which this contract inherits.
 */
contract NovaDecider is Groth16Verifier, KZG10Verifier, OpaqueDecider {
    /**
     * @notice  Computes the linear combination of a and b with r as the coefficient.
     * @dev     All ops are done mod the BN254 scalar field prime
     */
    function rlc(uint256 a, uint256 r, uint256 b) internal pure returns (uint256 result) {
        assembly {
            result := addmod(a, mulmod(r, b, BN254_SCALAR_FIELD), BN254_SCALAR_FIELD)
        }
    }

    /**
     * @notice  Verifies a nova cyclefold proof consisting of two KZG proofs and of a groth16 proof.
     * @dev     The selector of this function is "dynamic", since it depends on `z_len`.
     */
    function verifyNovaProof(
        // inputs are grouped to prevent errors due stack too deep
        uint256[9] calldata i_z0_zi, // [i, z0, zi] where |z0| == |zi|
        uint256[4] calldata U_i_cmW_U_i_cmE, // [U_i_cmW[2], U_i_cmE[2]]
        uint256[2] calldata u_i_cmW, // [u_i_cmW[2]]
        uint256[3] calldata cmT_r, // [cmT[2], r]
        uint256[2] calldata pA, // groth16 
        uint256[2][2] calldata pB, // groth16
        uint256[2] calldata pC, // groth16
        uint256[4] calldata challenge_W_challenge_E_kzg_evals, // [challenge_W, challenge_E, eval_W, eval_E]
        uint256[2][2] calldata kzg_proof // [proof_W, proof_E]
    ) public view returns (bool) {

        require(i_z0_zi[0] >= 2, "Folding: the number of folded steps should be at least 2");

        // from gamma_abc_len, we subtract 1. 
        uint256[44] memory public_inputs; 

        public_inputs[0] = 4744446173472907860520995574052063587209229277884496919768165727038465644594;
        public_inputs[1] = i_z0_zi[0];

        for (uint i = 0; i < 8; i++) {
            public_inputs[2 + i] = i_z0_zi[1 + i];
        }

        {
            // U_i.cmW + r * u_i.cmW
            uint256[2] memory mulScalarPoint = super.mulScalar([u_i_cmW[0], u_i_cmW[1]], cmT_r[2]);
            uint256[2] memory cmW = super.add([U_i_cmW_U_i_cmE[0], U_i_cmW_U_i_cmE[1]], mulScalarPoint);

            {
                uint256[5] memory cmW_x_limbs = LimbsDecomposition.decompose(cmW[0]);
                uint256[5] memory cmW_y_limbs = LimbsDecomposition.decompose(cmW[1]);
        
                for (uint8 k = 0; k < 5; k++) {
                    public_inputs[10 + k] = cmW_x_limbs[k];
                    public_inputs[15 + k] = cmW_y_limbs[k];
                }
            }
        
            require(this.check(cmW, kzg_proof[0], challenge_W_challenge_E_kzg_evals[0], challenge_W_challenge_E_kzg_evals[2]), "KZG: verifying proof for challenge W failed");
        }

        {
            // U_i.cmE + r * cmT
            uint256[2] memory mulScalarPoint = super.mulScalar([cmT_r[0], cmT_r[1]], cmT_r[2]);
            uint256[2] memory cmE = super.add([U_i_cmW_U_i_cmE[2], U_i_cmW_U_i_cmE[3]], mulScalarPoint);

            {
                uint256[5] memory cmE_x_limbs = LimbsDecomposition.decompose(cmE[0]);
                uint256[5] memory cmE_y_limbs = LimbsDecomposition.decompose(cmE[1]);
            
                for (uint8 k = 0; k < 5; k++) {
                    public_inputs[20 + k] = cmE_x_limbs[k];
                    public_inputs[25 + k] = cmE_y_limbs[k];
                }
            }

            require(this.check(cmE, kzg_proof[1], challenge_W_challenge_E_kzg_evals[1], challenge_W_challenge_E_kzg_evals[3]), "KZG: verifying proof for challenge E failed");
        }

        {
            // add challenges
            public_inputs[30] = challenge_W_challenge_E_kzg_evals[0];
            public_inputs[31] = challenge_W_challenge_E_kzg_evals[1];
            public_inputs[32] = challenge_W_challenge_E_kzg_evals[2];
            public_inputs[33] = challenge_W_challenge_E_kzg_evals[3];

            uint256[5] memory cmT_x_limbs;
            uint256[5] memory cmT_y_limbs;
        
            cmT_x_limbs = LimbsDecomposition.decompose(cmT_r[0]);
            cmT_y_limbs = LimbsDecomposition.decompose(cmT_r[1]);
        
            for (uint8 k = 0; k < 5; k++) {
                public_inputs[30 + 4 + k] = cmT_x_limbs[k]; 
                public_inputs[35 + 4 + k] = cmT_y_limbs[k];
            }

            bool success_g16 = this.verifyProof(pA, pB, pC, public_inputs);
            require(success_g16 == true, "Groth16: verifying proof failed");
        }

        return(true);
    }

    /**
     * @notice  Verifies a Nova+CycleFold proof given initial and final IVC states, number of steps and the rest proof inputs concatenated.
     * @dev     Simply reorganization of arguments and call to the `verifyNovaProof` function.
     */
    function verifyOpaqueNovaProofWithInputs(
        uint256 steps,
        uint256[4] calldata initial_state,
        uint256[4] calldata final_state,
        uint256[25] calldata proof
    ) public override view returns (bool) {
        uint256[1 + 2 * 4] memory i_z0_zi;
        i_z0_zi[0] = steps;
        for (uint256 i = 0; i < 4; i++) {
            i_z0_zi[i + 1] = initial_state[i];
            i_z0_zi[i + 1 + 4] = final_state[i];
        }

        uint256[4] memory U_i_cmW_U_i_cmE = [proof[0], proof[1], proof[2], proof[3]];
        uint256[2] memory u_i_cmW = [proof[4], proof[5]];
        uint256[3] memory cmT_r = [proof[6], proof[7], proof[8]];
        uint256[2] memory pA = [proof[9], proof[10]];
        uint256[2][2] memory pB = [[proof[11], proof[12]], [proof[13], proof[14]]];
        uint256[2] memory pC = [proof[15], proof[16]];
        uint256[4] memory challenge_W_challenge_E_kzg_evals = [proof[17], proof[18], proof[19], proof[20]];
        uint256[2][2] memory kzg_proof = [[proof[21], proof[22]], [proof[23], proof[24]]];

        return this.verifyNovaProof(
            i_z0_zi,
            U_i_cmW_U_i_cmE,
            u_i_cmW,
            cmT_r,
            pA,
            pB,
            pC,
            challenge_W_challenge_E_kzg_evals,
            kzg_proof
        );
    }

    /**
     * @notice  Verifies a Nova+CycleFold proof given all proof inputs concatenated.
     * @dev     Simply reorganization of arguments and call to the `verifyNovaProof` function.
     */
    function verifyOpaqueNovaProof(uint256[34] calldata proof) public override view returns (bool) {
        uint256[4] memory z0;
        uint256[4] memory zi;
        for (uint256 i = 0; i < 4; i++) {
            z0[i] = proof[i + 1];
            zi[i] = proof[i + 1 + 4];
        }

        uint256[25] memory extracted_proof;
        for (uint256 i = 0; i < 25; i++) {
            extracted_proof[i] = proof[9 + i];
        }

        return this.verifyOpaqueNovaProofWithInputs(proof[0], z0, zi, extracted_proof);
    }
}