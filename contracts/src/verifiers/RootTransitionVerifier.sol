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
            8194714635434497375410243095136417616521316131427339117406089196077538289324,
            3462409326708393646321328142804378493183834074120278548714725386956714268183
    ];
    uint256[2][2] G_2 = [
        [
            16107125551315195171643484369572325386759715747763579919463881552166217015666,
            1279434043692360453656453311175976947407033140834903656630327157150421405527
        ],
        [
            16537985636155246959363051258559653612137644953136816352678379759851981093082,
            20656628076326848130421170521490895976017053784037694294811284327430222422147
        ]
    ];
    uint256[2][2] VK = [
        [
            7483698262101103626442603990247719395542565520141926727191792034970016312646,
            12544950248295103259427812604778322078098890339907390102916561711520954912840
        ],
        [
            21069634062927718097569566265653089503869116325760116103611592944371459729859,
            9178893941190692343173664190940637731165923058120491199267046703641101539726
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
    uint256 constant alphax  = 969309562847223781795765733123518791003658982011589276922898624094175409321;
    uint256 constant alphay  = 13772924284495971814760170627993190669839609684866972133946115515739344650536;
    uint256 constant betax1  = 14873318924205388740091178427747587705150813956004108481225083446762595211484;
    uint256 constant betax2  = 9013221017529160326315418348084210367028059821588160630774971350751566489173;
    uint256 constant betay1  = 13123773570497402631907021157486859741875942922334232357766674617798068321815;
    uint256 constant betay2  = 765609787350300795296377108278371903559184952855958616436788734990803032454;
    uint256 constant gammax1 = 4235887566412799955049565788970509809053297445424932751200456028189069917102;
    uint256 constant gammax2 = 18134460437827946054307103988854696167166873037841980699041085134525308561769;
    uint256 constant gammay1 = 12048396478509598254419776827702608596877839296775500374280583846244819172427;
    uint256 constant gammay2 = 5034872517000331992063697101915921305842928208335679565225847618689377984757;
    uint256 constant deltax1 = 16069620469576492178867948099394645472688364247210984393583634494815930675935;
    uint256 constant deltax2 = 9227229548365619005741353997616705837403837726488530120054055781693455019359;
    uint256 constant deltay1 = 13510697663105810227124839713154658373436338762815919951288349513266465585363;
    uint256 constant deltay2 = 9265457655256008762679761682922392489696123569665862452692469045718999881041;

    
    uint256 constant IC0x = 9639594842890900651747624270281637925879729124358510403426495376316309262460;
    uint256 constant IC0y = 12332208651249047939705724746456279437059898899662460301277969028627113696160;
    
    uint256 constant IC1x = 13617145466091421000175644677379909655139170530722564303120174165315562068780;
    uint256 constant IC1y = 16198978853628061676275808732228492071812948238233189658082502371558446687972;
    
    uint256 constant IC2x = 4792705846953822981061373406354609244886047491963497721505863237851870198934;
    uint256 constant IC2y = 9515174963034110975227433335389334082566233254852207222792385712480888291602;
    
    uint256 constant IC3x = 19617178038930289451849721502826984705426300831190165356131986320210293377944;
    uint256 constant IC3y = 13877157615354399108461167556967208523664596122766145156039830116654285779075;
    
    uint256 constant IC4x = 10829309832697603419676851834193536577135238417750780638315145416702196109260;
    uint256 constant IC4y = 18579708354245316941867429963384109961848309426720613714513185965190850238432;
    
    uint256 constant IC5x = 8932458801906923970258342139625074778475881646433708348377235885269917156737;
    uint256 constant IC5y = 13446020070474946345099904614521423360554059249852883786581115979697254290954;
    
    uint256 constant IC6x = 13287912829298477484712930014540446022997570477699034431130100960324612852862;
    uint256 constant IC6y = 18183389937043649748025138887367032201847736376380086542708409156512688386280;
    
    uint256 constant IC7x = 24944486047663148491424247127935012074436162796017698369162684850691803443;
    uint256 constant IC7y = 17076624169666691754591790245136896171703341980092074278041332933617706000790;
    
    uint256 constant IC8x = 7528960688788573021067962119040486571218836355975127619915623555695012211654;
    uint256 constant IC8y = 7266112640093407019351502630890237037358936044187773804333319532549952295624;
    
    uint256 constant IC9x = 18257542935429439162743161931538382742777301926702949019404890801431256652373;
    uint256 constant IC9y = 21083690567344226022032545745758420184217615180542541549095740963192391106842;
    
    uint256 constant IC10x = 11837136063505567938350498188672762626123589076271372944735333887231757992582;
    uint256 constant IC10y = 6372282673188072555030513991591668035828827302946182324120169691098801056283;
    
    uint256 constant IC11x = 856449360095008166159713026794832689659304177690508287286059629520697997544;
    uint256 constant IC11y = 4007911083882049396913593290920999656259444462664379158954043640669939290210;
    
    uint256 constant IC12x = 12365596695077795945795268936422051150067261179655454355695049505064027741278;
    uint256 constant IC12y = 12072454379457848655730274764982493212391850818582736469960267693215986351548;
    
    uint256 constant IC13x = 2648166814829701904623074866636278756262000165903604363770862891658186578439;
    uint256 constant IC13y = 19029037184183144429722934810465999733594697868619497029453016499145060069168;
    
    uint256 constant IC14x = 11885922732695702437858579415432083245989984223200086476259224455240736484521;
    uint256 constant IC14y = 10290601325997572486807058142117365325827359438114802860391849805678841904362;
    
    uint256 constant IC15x = 1493536795143459272092810968145145629913140054126707586428130738287753440254;
    uint256 constant IC15y = 8480570135603228293833337248889326525549898777501352206207120215190208505873;
    
    uint256 constant IC16x = 5655099486256407326095517803020603884926309699094293224257038490919814476729;
    uint256 constant IC16y = 17512449365599337172381818039745847069776201806098406920125533325395063747120;
    
    uint256 constant IC17x = 9074351994036434057432514162558296929374372869255174667780073540430894216851;
    uint256 constant IC17y = 418524571939067859549253223915684565172124817051963814612761027963353651070;
    
    uint256 constant IC18x = 13203961323430611958506489025416509486025401406056942029733560869666217059483;
    uint256 constant IC18y = 4784812543346469517406443033872898670192296207858759054047169448408029114197;
    
    uint256 constant IC19x = 15073528581835832179091019956861677645468846865382661012099275668712723663694;
    uint256 constant IC19y = 20408629092846957670358029172047748704806734196209981271040537863666778177218;
    
    uint256 constant IC20x = 8556479593014055844295834899225530986080337506964685575045626680542421166482;
    uint256 constant IC20y = 19775410748983808104962451995731435276462477384378180960264385510183912126133;
    
    uint256 constant IC21x = 16182494924536136897089181757795052118936447235330152715243508663243507393492;
    uint256 constant IC21y = 2895218654904201872674783089579260279333561427245663677564450624790273979507;
    
    uint256 constant IC22x = 14925573284665040123095297099995658109045462931647219766589892089556720754946;
    uint256 constant IC22y = 9576705630010341894513942248180850486853298048563140477356869740736414161545;
    
    uint256 constant IC23x = 13469720578209268295485234406621507277591161685036973246211670996174509364221;
    uint256 constant IC23y = 20235070590743001365503958343432782078943302976472781611489149307163707942291;
    
    uint256 constant IC24x = 2889989220684442829661297760607226912366583731947279942357707597040652343236;
    uint256 constant IC24y = 19528941028867800192071860129618408457924722182309093216382600132338022913521;
    
    uint256 constant IC25x = 18415873108478107457879142133189069525221104253165511747741081817960433410338;
    uint256 constant IC25y = 6837204480020550050654879542075901898855143233147271318968891024920047667819;
    
    uint256 constant IC26x = 17990016563190200848407764638178189211481207007975134978279675016596737336313;
    uint256 constant IC26y = 16667533580259036056984891103379821794520374991881935524365179171452439959372;
    
    uint256 constant IC27x = 4812255122177347416523940486083673230313094681140323512647387310119419778717;
    uint256 constant IC27y = 16671860121990876513998775793285183589321570810052314960887702519474301747956;
    
    uint256 constant IC28x = 3739990904250217719456945910750045525213475837950999284770635501819777747937;
    uint256 constant IC28y = 12034355613036248822781594658892803000132255653622016353513582176798447337480;
    
    uint256 constant IC29x = 1857707408033026464804056958903997086123539313078391545482476870159070201733;
    uint256 constant IC29y = 18564102450787714872627850604656375035730903622344969513550504366857465112676;
    
    uint256 constant IC30x = 8276961115463671760673830728834724328380527228030404240616970287787341400970;
    uint256 constant IC30y = 19805250968299772869541030181967765696416127855179751536915205287534937012765;
    
    uint256 constant IC31x = 3259263376669400481906047348254472428920315833975044081202867080202112725932;
    uint256 constant IC31y = 17186827920249691923849128268115829732366045683223553091404684031078669708070;
    
    uint256 constant IC32x = 16028769669437743735206459335103754869316756343325404720588651632774203060101;
    uint256 constant IC32y = 8672763949992991373474797259601676493416274306849925815150686453440295419837;
    
    uint256 constant IC33x = 15731722740095460783593185679285758868504270085937683614116371720981432262729;
    uint256 constant IC33y = 6597247488202358183179848650448561319920178135270553216500432509970691819859;
    
    uint256 constant IC34x = 9962321954585379236435639508273423234360169406982783242990362431915209156099;
    uint256 constant IC34y = 17020247122064267347954995797015736690591701670477344229763645074873617237506;
    
    uint256 constant IC35x = 10889327134001602207452685448439378192755075544115000374701404443640348542474;
    uint256 constant IC35y = 16473871459975528205134154410973590089910880685465322407408228522609181195418;
    
    uint256 constant IC36x = 21222021065672600009726688213930196260728261383159008228704064405115529603450;
    uint256 constant IC36y = 21395973838412940487219549327194835921431139673857399087909677652550432750700;
    
    uint256 constant IC37x = 3158858704739736898338570916763508649863208442336239961834850342465099551909;
    uint256 constant IC37y = 818946896260726391694370854370607241634338054830398070724404585068262961301;
    
    uint256 constant IC38x = 18915646918231922039358254813151602594476806175027349387025144819254721346636;
    uint256 constant IC38y = 8351799692664162788368097705977556187308798859573405686075397684062342823913;
    
    uint256 constant IC39x = 1026104371716990076961988490848163439040318981480725840709237434854390964980;
    uint256 constant IC39y = 18597709732132016652240805476569595670174904444642740519446316180945277110684;
    
    uint256 constant IC40x = 11870240146288362918561372503468163861779571888637772591305793376027858798979;
    uint256 constant IC40y = 10506138387185763756818788098860746281741591565043911984294432160859831773529;
    
    uint256 constant IC41x = 13622436855861336080440925960225471681749647450305279888188885688378487211438;
    uint256 constant IC41y = 11612596692995406273444029581118137625830747750520560793958590079929450635008;
    
    uint256 constant IC42x = 1122547900813687126244613537667870341602338926826378027784097178456737265331;
    uint256 constant IC42y = 18438146770598952434575353377917777146018934358195700658028381615728557210801;
    
    
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

        public_inputs[0] = 12815211679935333556617823166901842240097946738060010184680746931900236111908;
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