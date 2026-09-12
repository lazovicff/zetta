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
            15295557396520589471539709767289226552805029890417534078199574206874205187854,
            11328716083086862288811540754212703619012937558394836566444623691233312929497
    ];
    uint256[2][2] G_2 = [
        [
            7954761011647106011912575183935531968018876703759070549586064793532249613408,
            16577129081928785619431783780772992668061870466597164830726278258730536095457
        ],
        [
            2069013278361103394827268785462893004772160268382832361402625540690049006029,
            1607305769040470236503318641233473008377461105351895666684445051340628066160
        ]
    ];
    uint256[2][2] VK = [
        [
            18862628962692099053055355553245556295078310791087643065108633666352321055869,
            20943277228046349016320458021360334329808524150498676570125130567954554557804
        ],
        [
            2525480065666348380396993408134023234126034068812962235015611130513168599461,
            13880080351888577881975172074919936693191245179478953587103458269275463697914
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
    uint256 constant alphax  = 16986559152556570104340824914432227812527349117893387384257872029212220328320;
    uint256 constant alphay  = 16286629369306818175659334460245776523719813896840069404678876930372527765906;
    uint256 constant betax1  = 18338569268916266410941462344002449772914762826727391561934231392992345514385;
    uint256 constant betax2  = 14545609419699806162795302933469805989460028804778433374157875269380127447550;
    uint256 constant betay1  = 8303589210258137997461224225147867292202183505297999526082957093901909240226;
    uint256 constant betay2  = 14515915186720600906337279493215361975996471123294612809172731564529424280511;
    uint256 constant gammax1 = 13674511688690592921981870017704251620533913198430120005253433982228651540685;
    uint256 constant gammax2 = 13098983072684251453717602582073886830965596875382917382874368649267341683992;
    uint256 constant gammay1 = 10226096578407815623786874477953833439031118474602127980493950013654770317839;
    uint256 constant gammay2 = 20787695498651892117445152263992933266252949005301918186611922110050443721364;
    uint256 constant deltax1 = 5034699915169488589095476709872355009860391506298962805368337460914397240218;
    uint256 constant deltax2 = 1197317085811555436167642130135774736522316353456578210792381021294371079807;
    uint256 constant deltay1 = 17548877704710654172568834447733750890781342538629577340060674594914532811611;
    uint256 constant deltay2 = 8598999214293546567358475505819515728012744890411712767581825753981032241925;

    
    uint256 constant IC0x = 5324902359469445123954015145506616772772263937324161428788136987093006665952;
    uint256 constant IC0y = 8916261613557969568017874010899376253381978087687380811612600097279633852868;
    
    uint256 constant IC1x = 10923088646940076726876078023520282129747938208865497581085800382751008748628;
    uint256 constant IC1y = 14165160114956712182784610191952464858058536423311795454306725192816172456792;
    
    uint256 constant IC2x = 2983353125886981697142349166631074424234770032881286893232578494283404000250;
    uint256 constant IC2y = 16208597202550111630244141300198040256015092861395201314450984629553772280509;
    
    uint256 constant IC3x = 8050870637678720534240431249577548822242989616060449481422799921597545393745;
    uint256 constant IC3y = 5615873649122654237205380261581834627152700808261670158595273061952812956303;
    
    uint256 constant IC4x = 9243088633917698394342101523568149448044742712602691990646144033967451667393;
    uint256 constant IC4y = 12240698553121983777091261284986463447242962573717521720803402766481820786333;
    
    uint256 constant IC5x = 10323786563979945507758960044529911235669897449026033801903379975353529848360;
    uint256 constant IC5y = 4344315341101548363041630581511156034044625419593022253396821930199660389139;
    
    uint256 constant IC6x = 19505265443465657183604455511379550975966332111817781774942319170964169406508;
    uint256 constant IC6y = 6218197054199713879465211973456896127261444353363997527651101919211190825047;
    
    uint256 constant IC7x = 21363870798757828763572845074792904628256623564433971718740200896446098955782;
    uint256 constant IC7y = 18866046539002556831875853937253214774750720623164391924243273045706723786141;
    
    uint256 constant IC8x = 8767160884484847476428920365410337676566915980278071939881087455662428100011;
    uint256 constant IC8y = 18049929956070801373840784607263011593031803835356547601961802347644344787749;
    
    uint256 constant IC9x = 8673170876516585284035553915016989321072858259712417658126691040587298871179;
    uint256 constant IC9y = 20130926673932892684375302382526746333466119263807902410369847411219488202233;
    
    uint256 constant IC10x = 17456040064415944029888214734560065225596119195388858553844937191318908573174;
    uint256 constant IC10y = 6265033840666893016673064335551479025820808682358242573453214531687683945082;
    
    uint256 constant IC11x = 18721508803488469302826232290096938528081583663179847018775663309961306506273;
    uint256 constant IC11y = 17154675366312953152384638087709779183498212550673594658343495954528089565930;
    
    uint256 constant IC12x = 11196640144963740038657403538333761987092892181679893695587518622869316499284;
    uint256 constant IC12y = 12218234039530320645629233435292804368203622249582895449144048052239290627909;
    
    uint256 constant IC13x = 7429648518752435452500357267883094697071798010818638573080151409121917617224;
    uint256 constant IC13y = 18889744464491495009889636739774078576472458484776501644772700309210878809973;
    
    uint256 constant IC14x = 11326380311059438585135430932068562189648010200958267163319119435028655554030;
    uint256 constant IC14y = 3486031768884665582088242955873261762344365563195035982730930224710326388118;
    
    uint256 constant IC15x = 6108883690661931548786640857380130319734970654662996433324809633255493030803;
    uint256 constant IC15y = 17621915583582726644338040171318194232614006405756549730722110156421758049607;
    
    uint256 constant IC16x = 18548027919953282004713566714878045388827340362649964197285210934994982351983;
    uint256 constant IC16y = 10757281725767887805515630799690228161540695409578710256673949009253527541178;
    
    uint256 constant IC17x = 15423763840951902640377819025401558033654343374654132959571264851121079944066;
    uint256 constant IC17y = 12017731859101113223959162895926450785570519359323845081291852033820736769704;
    
    uint256 constant IC18x = 7323340856236148276181573191945368987950632242462001700209106050390125793121;
    uint256 constant IC18y = 8587614481982825805181317704971951755674581063760570070648795027344470947926;
    
    uint256 constant IC19x = 19909681552390262328356919309852258836770765936582288600020793357791518320379;
    uint256 constant IC19y = 12698737054984001098664607073071471372760136509533687343385966119850623547940;
    
    uint256 constant IC20x = 8119776667892675757944552105259936818202050820800645317017946745053797190319;
    uint256 constant IC20y = 4671907715360084592207956728419584052431669404541183855159612640904345189997;
    
    uint256 constant IC21x = 16533841098264980475084432669536515125795946253126322284200798803439101412365;
    uint256 constant IC21y = 1427030138015815765608225170742039288235256148244957813791292375295948863608;
    
    uint256 constant IC22x = 8094588607986194155866103402762523066938579710757976494585373150384891446486;
    uint256 constant IC22y = 4171927525892762347231855415077327726053868301512373351739438760571336531605;
    
    uint256 constant IC23x = 3864526026709775216788653330799432818364502626281602833445809199731224557964;
    uint256 constant IC23y = 21036648371598014714992894665506024377392563765660699656148783933351435668365;
    
    uint256 constant IC24x = 6761632618554444975960530617214212130188506720453167683167284533102406479017;
    uint256 constant IC24y = 11944733228913040073704689447692640531487521584368043083923967645820027406983;
    
    uint256 constant IC25x = 5819943392703278856295897688501484183844075350117514573243574193339233624796;
    uint256 constant IC25y = 1944689426397417089296045981688862321644236495311380695528834000189434678996;
    
    uint256 constant IC26x = 11077123038973158487701225687688942663334573883794610506584535612165707511980;
    uint256 constant IC26y = 748913351944456950624339789910449082348139635696897716403044179643394899053;
    
    uint256 constant IC27x = 10358061999575902228810131214295826477648310710540770467285070216511232541850;
    uint256 constant IC27y = 7870647032672976836217525376119626897313692794263048063071027439192320378190;
    
    uint256 constant IC28x = 4921209628971414249724520949474444699548234339391469059277645246338490864196;
    uint256 constant IC28y = 18233062563728409814158286237309453602641987711041584208715720586369042722417;
    
    uint256 constant IC29x = 18975698872736137125829351693058603662665352205727673787102582370411678225366;
    uint256 constant IC29y = 7936718202804442265609465101470657547529081291222440313349673380168008980177;
    
    uint256 constant IC30x = 10227175011171654793483749461424196752656552808040844939174228431392613470856;
    uint256 constant IC30y = 21585286806239635766487218322343504837140939914365247393184049347616474090160;
    
    uint256 constant IC31x = 11665465830241078748453240434188767832313771166883094427486499116273396414915;
    uint256 constant IC31y = 8213535238188174762513119258406114390311330639642184869395906573865675941099;
    
    uint256 constant IC32x = 13848687162368066205587121483630120315078708748184157528719311005320066933072;
    uint256 constant IC32y = 20751971227981037022991679658426520700256878944193235933080014099682722556457;
    
    uint256 constant IC33x = 12568533891205085043220331609230629538503328503790614561607037402889493121989;
    uint256 constant IC33y = 6863660685298404300909722096291452196523488420560241148202184967132715444466;
    
    uint256 constant IC34x = 19120192599028039426864937593149949677873460682603711328305291381194932096808;
    uint256 constant IC34y = 2314582222677148527357396133045828954681747458136518852852843134131745685722;
    
    uint256 constant IC35x = 13241717946659565822381057509268618965711447555602972875725891922706811124644;
    uint256 constant IC35y = 18135805331420702998337140043156955498505687080600223360440788713756751561081;
    
    uint256 constant IC36x = 11741294345968667160721165848980625932360056242534576265586217121615931175644;
    uint256 constant IC36y = 11564895540804008928617521426722179950792581377721108356344662414150782242021;
    
    uint256 constant IC37x = 11767018269987486421393497984372684033377866046778533189556893248961120570145;
    uint256 constant IC37y = 11233905242951336707515282919195705028595657220619266153336063104373761213046;
    
    uint256 constant IC38x = 15785735242922548519121954962752680026560146749280970693785655594651845636709;
    uint256 constant IC38y = 20725015229399163082614405119942965557790983713567122210567814710485110667730;
    
    uint256 constant IC39x = 17638191891441667795669513548201696336910638704090192009580971683908863018707;
    uint256 constant IC39y = 14700168620200792402779435263000542355761746704949316077895026104482381102709;
    
    uint256 constant IC40x = 10306455192649332706697427610492817409195156391447751135477836279215722833249;
    uint256 constant IC40y = 2129806546933318902771695966631402521763823557327449241195537774012773913681;
    
    uint256 constant IC41x = 21031579575319788361011252671662414427102731039761742112336791615648712064946;
    uint256 constant IC41y = 3686121218781307819476764115117939928242672875580590895423049598472181551551;
    
    uint256 constant IC42x = 8133287976308369244455057761140096714138256269088077762616134103262917020201;
    uint256 constant IC42y = 10968916592513577155270963528304308909159675955976089049939190129756720842316;
    
    
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[42] calldata _pubSignals) public view returns (bool) {
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
        uint256[3] calldata initial_state, // initial IVC state (z0)
        uint256[3] calldata final_state, // IVC state after i steps (zi)
        uint256[25] calldata proof // the rest of the decider inputs
    ) external view returns (bool);

    /**
     * @notice  Verifies a Nova+CycleFold proof given all the proof inputs collected in a single array.
     * @dev     This function should simply reorganize arguments and pass them to the proper verification function.
     */
    function verifyOpaqueNovaProof(uint256[32] calldata proof) external view returns (bool);
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
        uint256[7] calldata i_z0_zi, // [i, z0, zi] where |z0| == |zi|
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
        uint256[42] memory public_inputs; 

        public_inputs[0] = 3713327450643854356294713980517362177514773188378187272683044041008562354335;
        public_inputs[1] = i_z0_zi[0];

        for (uint i = 0; i < 6; i++) {
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
                    public_inputs[8 + k] = cmW_x_limbs[k];
                    public_inputs[13 + k] = cmW_y_limbs[k];
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
                    public_inputs[18 + k] = cmE_x_limbs[k];
                    public_inputs[23 + k] = cmE_y_limbs[k];
                }
            }

            require(this.check(cmE, kzg_proof[1], challenge_W_challenge_E_kzg_evals[1], challenge_W_challenge_E_kzg_evals[3]), "KZG: verifying proof for challenge E failed");
        }

        {
            // add challenges
            public_inputs[28] = challenge_W_challenge_E_kzg_evals[0];
            public_inputs[29] = challenge_W_challenge_E_kzg_evals[1];
            public_inputs[30] = challenge_W_challenge_E_kzg_evals[2];
            public_inputs[31] = challenge_W_challenge_E_kzg_evals[3];

            uint256[5] memory cmT_x_limbs;
            uint256[5] memory cmT_y_limbs;
        
            cmT_x_limbs = LimbsDecomposition.decompose(cmT_r[0]);
            cmT_y_limbs = LimbsDecomposition.decompose(cmT_r[1]);
        
            for (uint8 k = 0; k < 5; k++) {
                public_inputs[28 + 4 + k] = cmT_x_limbs[k]; 
                public_inputs[33 + 4 + k] = cmT_y_limbs[k];
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
        uint256[3] calldata initial_state,
        uint256[3] calldata final_state,
        uint256[25] calldata proof
    ) public override view returns (bool) {
        uint256[1 + 2 * 3] memory i_z0_zi;
        i_z0_zi[0] = steps;
        for (uint256 i = 0; i < 3; i++) {
            i_z0_zi[i + 1] = initial_state[i];
            i_z0_zi[i + 1 + 3] = final_state[i];
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
    function verifyOpaqueNovaProof(uint256[32] calldata proof) public override view returns (bool) {
        uint256[3] memory z0;
        uint256[3] memory zi;
        for (uint256 i = 0; i < 3; i++) {
            z0[i] = proof[i + 1];
            zi[i] = proof[i + 1 + 3];
        }

        uint256[25] memory extracted_proof;
        for (uint256 i = 0; i < 25; i++) {
            extracted_proof[i] = proof[7 + i];
        }

        return this.verifyOpaqueNovaProofWithInputs(proof[0], z0, zi, extracted_proof);
    }
}