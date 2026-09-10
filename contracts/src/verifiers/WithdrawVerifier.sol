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
            1299892000962107877010932217398377927627136948951481551209899826409326728227,
            14694903540656916728802459079332741412259260738832710088738387894461986138192
    ];
    uint256[2][2] G_2 = [
        [
            957047464207034255382434634820111671358052226067404841061594213130669658839,
            10087921715581164667201596829372067833815661765912954989818488568567755650884
        ],
        [
            11049765039821886224767440269960816871288068664141773846270270875771198065280,
            18652347284892399278029115602669300351044069716096149148488251583346740098023
        ]
    ];
    uint256[2][2] VK = [
        [
            6521079607399667479397961126814662676691904508347650901390215228733237221012,
            8020180229426011621088320719983914269064779107929657588804539384362897549074
        ],
        [
            11353724552050957544262510733066517093512992107651206031613998865731313805783,
            528356772927656893677578616569456966222386875050283954290522471083642642451
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
    uint256 constant alphax  = 17690296552545302303760078966156655842702438746996529860961003881306320598655;
    uint256 constant alphay  = 18648141250164954795201381504249266815845550779565028854355717353638429482940;
    uint256 constant betax1  = 11195407232685089765299054775385884500073853439188334432782831964664736399139;
    uint256 constant betax2  = 4780790436412501385785230389737006004531779230818132390770953856835614501309;
    uint256 constant betay1  = 15557294558170791634762915934569947001634748719267726967614124065694665319509;
    uint256 constant betay2  = 9560666165965248593785173550856175165608251893056432103317574482509265633685;
    uint256 constant gammax1 = 14775529145158564271477513803623453540910601755707927754713093275198459257874;
    uint256 constant gammax2 = 12031750718084607670394161945749778531060183853219696783079299625043000614189;
    uint256 constant gammay1 = 5917042895951662941424274206249821039536179953934211846524921867462434996951;
    uint256 constant gammay2 = 18578133916219373092318365037698512805286778832953400998860819329301839413345;
    uint256 constant deltax1 = 12229442941404818585737792682953236987893840127153225028628641615647204351784;
    uint256 constant deltax2 = 17854046498053632239673166457168593290602583366649967576543195805935160048456;
    uint256 constant deltay1 = 198220272962465788948907522614823716179396180288608488786143977230064159357;
    uint256 constant deltay2 = 12226345092082440763829170294501408537567207196206217094593318506870558907714;

    
    uint256 constant IC0x = 20015715261916955620916137991495348962962879184935586686013587480825342127359;
    uint256 constant IC0y = 4407292707078607832358152281993811109353245691167699045674564635320930051180;
    
    uint256 constant IC1x = 10134494457726152409202008595290399699712833575412335298775732694296616812793;
    uint256 constant IC1y = 16685695628524779142925514477915909763375823372189512135940881235262083966205;
    
    uint256 constant IC2x = 5212111653724216318421122872014594260257867774402158871430136843181159561142;
    uint256 constant IC2y = 21732260214317552775462502059883995859828606663835361814499081921451493156017;
    
    uint256 constant IC3x = 327565177164122234200356372954689689785131505695438492355296863597774290775;
    uint256 constant IC3y = 2722841152921025754922199410459932625915375095063311133757536864577179431537;
    
    uint256 constant IC4x = 7745225521712027155373244123751304537033932197869639137436203684742087555778;
    uint256 constant IC4y = 5698906113957278623700394147651995463785299380101785274899961748034248727111;
    
    uint256 constant IC5x = 6156686301943086183995459128675842809542008553938160239356189017951507711235;
    uint256 constant IC5y = 10402249657689285815398917514526588345021395586862282920406178025823338367178;
    
    uint256 constant IC6x = 189556989827099722114932660631768500559629721989757628563185563158963268735;
    uint256 constant IC6y = 19601823963760164808813658942442872271770713144263365042382716575042535602682;
    
    uint256 constant IC7x = 21257465130966044253326714419492866741485001806312013912464020489230908882329;
    uint256 constant IC7y = 10490025314000633377275747411545263257128343890917319004093767356382906501890;
    
    uint256 constant IC8x = 18155985512624446775174807388232725210475273274923477418109699704613281072725;
    uint256 constant IC8y = 11651518027580939988967621690500204768612662951332665348518303597502883845618;
    
    uint256 constant IC9x = 16251248172057962334187445330864219355143968899249555653122684109366801236571;
    uint256 constant IC9y = 17340111282986883349657218711522684771892500124363105074524220129277968349381;
    
    uint256 constant IC10x = 4737223706340070242293783711418064135352514700004521717734079337225202922602;
    uint256 constant IC10y = 11589311750487598166259866029282947636542970776941290591884135289868038626735;
    
    uint256 constant IC11x = 3258682906078760960813889390878337017944623686598163603702177694576178273706;
    uint256 constant IC11y = 2945428419175403234648223768515677566425902624506478625254706244484543005950;
    
    uint256 constant IC12x = 3261493957019388140641475901701903425586892011604353088744343621882118562135;
    uint256 constant IC12y = 2556143861501541136920646675497668769825890187155970428368521998789019899274;
    
    uint256 constant IC13x = 17474014170614303591377235678173263208506488497737060321119326474289051509126;
    uint256 constant IC13y = 14347769610758087499992966948612175160048491685915498409326351720637980244046;
    
    uint256 constant IC14x = 2267576689039425608351379109955651826381242149995443897146122167493329086592;
    uint256 constant IC14y = 18356832316833198839776725338826119957989942454083460161311179229114102695867;
    
    uint256 constant IC15x = 19053769020925103503281946185899604069393220794117141304453227623939363045312;
    uint256 constant IC15y = 19333994796122226821431144997642726710156814277159202238883179546909734959767;
    
    uint256 constant IC16x = 30741758949200445198352592599945995962707761691139438484828354744318383201;
    uint256 constant IC16y = 7463119995453371293874368789914457621937750222146134034735494827002556966987;
    
    uint256 constant IC17x = 5934092852429045716555548601585487608167456943782179985686302904717940754349;
    uint256 constant IC17y = 19338579287760299958322443292780148144956019469082025212997410934953220963891;
    
    uint256 constant IC18x = 17009603216988044909720647933515580498605604250169485791686570072351170130386;
    uint256 constant IC18y = 1327786977474015061487835976823639154033710006018565328182664180818636960923;
    
    uint256 constant IC19x = 19682250974658852869818295674259094979067647601960182461522151804431711658618;
    uint256 constant IC19y = 21803801692243858529966884038436634683395837924135921377833690618624082974405;
    
    uint256 constant IC20x = 7715750452708474543764164240937617429191510617411720121093581162553108685997;
    uint256 constant IC20y = 20139332699067290340203276897042100964990866849375491846856082101402460812373;
    
    uint256 constant IC21x = 13849852253079312619777112838869676705157815354786843826585652423324690145255;
    uint256 constant IC21y = 13958391976966165182941292071688282538135268154445141163062849206623661113427;
    
    uint256 constant IC22x = 4045216625959978015241035855445234573868886305235703181208605843225572784538;
    uint256 constant IC22y = 10250873243571906136201667851658717064019433246669712923807347548912335162287;
    
    uint256 constant IC23x = 18547558727848859315926793450006987489298553817759000757511031420227681387582;
    uint256 constant IC23y = 21496070930055457084647312986400092248911276700018015268393691788093363846957;
    
    uint256 constant IC24x = 13084619553322943548794778766462333015326066642965902822264111407579313286361;
    uint256 constant IC24y = 6818635487517015882540791163198260167174919032813129732187087963865091244605;
    
    uint256 constant IC25x = 12444055301124765318171420484198164822763500881343050495137060481628731867688;
    uint256 constant IC25y = 3425259843971786253269442195218383936546449338519480336877949561542292673527;
    
    uint256 constant IC26x = 9178956096924551145305564813000552654027519906500652222690260737720811671950;
    uint256 constant IC26y = 17266076490342212755435379550420223142599287088898255892177018460634220773672;
    
    uint256 constant IC27x = 7446247410196149820736692692674495319520847192044563299762902808018046552769;
    uint256 constant IC27y = 11036066231255949229575705886846230440663024196774459535844888654167444115699;
    
    uint256 constant IC28x = 11359296099510122559472719679587834914477426080945621816618496750761438580621;
    uint256 constant IC28y = 7964440460247624236217226712152933517116193561467578033748330763748827530451;
    
    uint256 constant IC29x = 17682582397590995340892787332065628891249535706894923483054589482639627097413;
    uint256 constant IC29y = 20238335708583406911418349072563977496738673448299895970377430683035907500892;
    
    uint256 constant IC30x = 20934722584472617225400978713893575711581525824293202452703332934146710422384;
    uint256 constant IC30y = 15100310871778785484046446146256903766868006049567133268238734150655134832248;
    
    uint256 constant IC31x = 15514696459216551870275078254682745747223707832473450230291371559405953778027;
    uint256 constant IC31y = 21271264970860903818081765751875864634516334348151429577581629600949508333671;
    
    uint256 constant IC32x = 3362615736480256318710514652293998999540378875114778335855653299185964351702;
    uint256 constant IC32y = 14983716192689973664945331560717176353145809197283229879532906947896651008245;
    
    uint256 constant IC33x = 6512422067903835631704377666611531983416168109482945284825157416702476123533;
    uint256 constant IC33y = 13359970712138800004999781249513049514103725716218651318337204030883488705875;
    
    uint256 constant IC34x = 7810512602952558944858637258480317042954160110054841235376509204468172355995;
    uint256 constant IC34y = 16424599123631415998332123290701740729982160127837289171252931268112184997996;
    
    uint256 constant IC35x = 13701457624918526616217681616917216367368752061080700708907598956061323950067;
    uint256 constant IC35y = 12808346888167808791346931463878244286662999956066046117578056051055922479438;
    
    uint256 constant IC36x = 13314481511220202564351038146699870797198401461684504667010259156633461369739;
    uint256 constant IC36y = 17367963592684665764550545198051033215639305320886875114138723637223482422727;
    
    uint256 constant IC37x = 14456988473581243993573352822780592229422124676380874876384140955063222169007;
    uint256 constant IC37y = 12569647320998830211966182355327686015551191429023859571625673321587573881395;
    
    uint256 constant IC38x = 3612661149581843953594431479546051795535892009217874131197441474102392280041;
    uint256 constant IC38y = 7813310294022740981538663052409990363447578416703635597117793611659660472814;
    
    uint256 constant IC39x = 18305071046586187679790740584425682189357444940502697597672590814428389190267;
    uint256 constant IC39y = 13292303810064929151697815264333416632685520677024311138056300895436627000087;
    
    uint256 constant IC40x = 13522963470439288582951848739004045725100792004781941863815300763162177678237;
    uint256 constant IC40y = 14183993744811792274709825748515805125835294941140340583328280426323818030989;
    
    uint256 constant IC41x = 20669688945917800258495672644159431135365587242857128367381130450148326539731;
    uint256 constant IC41y = 21784197047326932020221562711085048458499160326675668918343969619429043261556;
    
    uint256 constant IC42x = 10671719229686917232738360138231391479400078776513483163351704283165859679457;
    uint256 constant IC42y = 10979252776617268880259342941324928366344911225277063356983068509998033094014;
    
    uint256 constant IC43x = 6183258082563866619002179046933729681938569630145975799606729908416194921465;
    uint256 constant IC43y = 13541232738002966891347440601092258971065983052470845260269387043993962621694;
    
    uint256 constant IC44x = 12606231218430193301755338880203372418779448172505233437562205414635583312590;
    uint256 constant IC44y = 2372937804960474748778291589954240784435940053207671465491756721423086494869;
    
    
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

        public_inputs[0] = 10797018591304053368990351396214968635603077337985906924271880840464937147465;
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