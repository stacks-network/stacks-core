// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use stacks_common::util::uint::Uint256;

use crate::stacks_common::util::uint::BitArray;

/// A fixed-point numerical representation for ATC.  The integer and fractional parts are both 64
/// bits.  Internally, this is a Uint256 so that safe addition and multiplication can be done.
///
/// Bits 0-63 are the fraction.
/// Bits 64-127 are the integer.
/// Bits 128-256 are 0's to facilitate safe addition and multiplication.
///
/// The reasons we use this instead of f64 for ATC calculations are as follows:
/// * This avoids unrepresentable states, like NaN or +/- INF
/// * This avoids ambiguous states, like +0.0 and -0.0.
/// * This integrates better into the sortition-sampling system, which uses a u256 to represent a
/// probability range (which is what this is going to be used for)
#[derive(Debug, Clone, PartialEq, Copy, Eq, Hash)]
pub(crate) struct AtcRational(pub(crate) Uint256);
impl AtcRational {
    /// Construct from a fraction (numerator and denominator)
    pub fn frac(num: u64, den: u64) -> Self {
        Self((Uint256::from_u64(num) << 64) / Uint256::from_u64(den))
    }

    /// 0 value
    pub fn zero() -> Self {
        Self(Uint256::zero())
    }

    /// 1 value
    pub fn one() -> Self {
        Self(Uint256::one() << 64)
    }

    /// largest value less than 1
    pub fn one_sup() -> Self {
        Self((Uint256::one() << 64) - Uint256::from_u64(1))
    }

    /// Largest possible value (corresponds to u64::MAX.u64::MAX)
    pub fn max() -> Self {
        Self((Uint256::from_u64(u64::MAX) << 64) | Uint256::from_u64(u64::MAX))
    }

    /// Get integer part
    pub fn ipart(&self) -> u64 {
        (self.0 >> 64).low_u64()
    }

    /// Is this value overflowed?
    pub fn is_overflowed(&self) -> bool {
        self.0 > Self::max().0
    }

    /// Checked addition
    pub fn add(&self, other: &AtcRational) -> Option<Self> {
        // NOTE: this is always safe since u128::MAX + u128::MAX < Uint256::max()
        let sum = AtcRational(self.0 + other.0);
        if sum.is_overflowed() {
            return None;
        }
        Some(sum)
    }

    /// Checked subtraction
    pub fn sub(&self, other: &AtcRational) -> Option<Self> {
        if self.0 < other.0 {
            return None;
        }
        Some(AtcRational(self.0 - other.0))
    }

    /// Checked multiplication
    pub fn mul(&self, other: &AtcRational) -> Option<Self> {
        // NOTE: this is always safe since u128::MAX * u128::MAX < Uint256::max()
        let prod = AtcRational((self.0 * other.0) >> 64);
        if prod.is_overflowed() {
            return None;
        }
        Some(prod)
    }

    /// Minimum of self and other
    pub fn min(&self, other: &AtcRational) -> Self {
        if self.0 < other.0 {
            Self(self.0.clone())
        } else {
            Self(other.0.clone())
        }
    }

    /// Hex representation of the inner bits
    pub fn to_hex(&self) -> String {
        self.0.to_hex_be()
    }

    /// Inner u256 ref
    pub fn inner(&self) -> &Uint256 {
        &self.0
    }

    /// Inner u256, for conversion to something a BurnSamplePoint can use
    pub fn into_inner(self) -> Uint256 {
        self.0
    }

    /// Convert to a BurnSamplePoint probability for use in calculating a sortition
    pub fn into_sortition_probability(self) -> Uint256 {
        // AtcRational's fractional part is only 64 bits, so we need to scale it up so that it occupies the
        // upper 64 bits of the burn sample point ranges so as to accurately represent the fraction
        // of mining power the null miner has.
        let prob_u256 = if self.inner() >= Self::one().inner() {
            // prevent left-shift overflow
            Self::one_sup().into_inner() << 192
        } else {
            self.into_inner() << 192
        };
        prob_u256
    }
}

/// Pre-calculated 1024-member lookup table for the null miner advantage function, as AtcRational
/// fixed point integers.  The first item corresponds to the value of the function at 0.0, and the
/// last item corresponds to the function at 1.0 - (1.0 / 1024.0).  The input to a function is the
/// assumed total commit carryover -- the ratio between what the winning miner paid in this
/// block-commit to the median of what they historically paid (for an epoch-defined search window
/// size).  A value greater than 1.0 means that the miner paid all of the assumed commit
/// carry-over, and the null miner has negligible chances of winning.  A value less than 1.0 means
/// that the miner underpaid relative to their past performance, and the closer to 0.0 this ratio
/// is, the more likely the null miner wins and this miner loses.
///
/// This table is generated with `make_null_miner_lookup_table()` above.
pub(crate) const ATC_LOOKUP: [AtcRational; 1024] = [
    AtcRational(Uint256([14665006693661589504, 0, 0, 0])),
    AtcRational(Uint256([14663943061084833792, 0, 0, 0])),
    AtcRational(Uint256([14662867262262108160, 0, 0, 0])),
    AtcRational(Uint256([14661779159858638848, 0, 0, 0])),
    AtcRational(Uint256([14660678615031697408, 0, 0, 0])),
    AtcRational(Uint256([14659565487415023616, 0, 0, 0])),
    AtcRational(Uint256([14658439635103131648, 0, 0, 0])),
    AtcRational(Uint256([14657300914635431936, 0, 0, 0])),
    AtcRational(Uint256([14656149180980262912, 0, 0, 0])),
    AtcRational(Uint256([14654984287518758912, 0, 0, 0])),
    AtcRational(Uint256([14653806086028572672, 0, 0, 0])),
    AtcRational(Uint256([14652614426667460608, 0, 0, 0])),
    AtcRational(Uint256([14651409157956749312, 0, 0, 0])),
    AtcRational(Uint256([14650190126764625920, 0, 0, 0])),
    AtcRational(Uint256([14648957178289305600, 0, 0, 0])),
    AtcRational(Uint256([14647710156042049536, 0, 0, 0])),
    AtcRational(Uint256([14646448901830051840, 0, 0, 0])),
    AtcRational(Uint256([14645173255739158528, 0, 0, 0])),
    AtcRational(Uint256([14643883056116467712, 0, 0, 0])),
    AtcRational(Uint256([14642578139552755712, 0, 0, 0])),
    AtcRational(Uint256([14641258340864796672, 0, 0, 0])),
    AtcRational(Uint256([14639923493077501952, 0, 0, 0])),
    AtcRational(Uint256([14638573427405920256, 0, 0, 0])),
    AtcRational(Uint256([14637207973237102592, 0, 0, 0])),
    AtcRational(Uint256([14635826958111819776, 0, 0, 0])),
    AtcRational(Uint256([14634430207706118144, 0, 0, 0])),
    AtcRational(Uint256([14633017545812742144, 0, 0, 0])),
    AtcRational(Uint256([14631588794322399232, 0, 0, 0])),
    AtcRational(Uint256([14630143773204873216, 0, 0, 0])),
    AtcRational(Uint256([14628682300490010624, 0, 0, 0])),
    AtcRational(Uint256([14627204192248543232, 0, 0, 0])),
    AtcRational(Uint256([14625709262572754944, 0, 0, 0])),
    AtcRational(Uint256([14624197323557009408, 0, 0, 0])),
    AtcRational(Uint256([14622668185278134272, 0, 0, 0])),
    AtcRational(Uint256([14621121655775633408, 0, 0, 0])),
    AtcRational(Uint256([14619557541031794688, 0, 0, 0])),
    AtcRational(Uint256([14617975644951588864, 0, 0, 0])),
    AtcRational(Uint256([14616375769342470144, 0, 0, 0])),
    AtcRational(Uint256([14614757713894002688, 0, 0, 0])),
    AtcRational(Uint256([14613121276157339648, 0, 0, 0])),
    AtcRational(Uint256([14611466251524579328, 0, 0, 0])),
    AtcRational(Uint256([14609792433207912448, 0, 0, 0])),
    AtcRational(Uint256([14608099612218703872, 0, 0, 0])),
    AtcRational(Uint256([14606387577346342912, 0, 0, 0])),
    AtcRational(Uint256([14604656115137021952, 0, 0, 0])),
    AtcRational(Uint256([14602905009872304128, 0, 0, 0])),
    AtcRational(Uint256([14601134043547590656, 0, 0, 0])),
    AtcRational(Uint256([14599342995850407936, 0, 0, 0])),
    AtcRational(Uint256([14597531644138579968, 0, 0, 0])),
    AtcRational(Uint256([14595699763418222592, 0, 0, 0])),
    AtcRational(Uint256([14593847126321623040, 0, 0, 0])),
    AtcRational(Uint256([14591973503084957696, 0, 0, 0])),
    AtcRational(Uint256([14590078661525866496, 0, 0, 0])),
    AtcRational(Uint256([14588162367020904448, 0, 0, 0])),
    AtcRational(Uint256([14586224382482810880, 0, 0, 0])),
    AtcRational(Uint256([14584264468337694720, 0, 0, 0])),
    AtcRational(Uint256([14582282382502025216, 0, 0, 0])),
    AtcRational(Uint256([14580277880359520256, 0, 0, 0])),
    AtcRational(Uint256([14578250714737874944, 0, 0, 0])),
    AtcRational(Uint256([14576200635885367296, 0, 0, 0])),
    AtcRational(Uint256([14574127391447336960, 0, 0, 0])),
    AtcRational(Uint256([14572030726442487808, 0, 0, 0])),
    AtcRational(Uint256([14569910383239120896, 0, 0, 0])),
    AtcRational(Uint256([14567766101531174912, 0, 0, 0])),
    AtcRational(Uint256([14565597618314184704, 0, 0, 0])),
    AtcRational(Uint256([14563404667861078016, 0, 0, 0])),
    AtcRational(Uint256([14561186981697867776, 0, 0, 0])),
    AtcRational(Uint256([14558944288579205120, 0, 0, 0])),
    AtcRational(Uint256([14556676314463823872, 0, 0, 0])),
    AtcRational(Uint256([14554382782489843712, 0, 0, 0])),
    AtcRational(Uint256([14552063412949977088, 0, 0, 0])),
    AtcRational(Uint256([14549717923266603008, 0, 0, 0])),
    AtcRational(Uint256([14547346027966732288, 0, 0, 0])),
    AtcRational(Uint256([14544947438656860160, 0, 0, 0])),
    AtcRational(Uint256([14542521863997716480, 0, 0, 0])),
    AtcRational(Uint256([14540069009678876672, 0, 0, 0])),
    AtcRational(Uint256([14537588578393323520, 0, 0, 0])),
    AtcRational(Uint256([14535080269811841024, 0, 0, 0])),
    AtcRational(Uint256([14532543780557377536, 0, 0, 0])),
    AtcRational(Uint256([14529978804179232768, 0, 0, 0])),
    AtcRational(Uint256([14527385031127242752, 0, 0, 0])),
    AtcRational(Uint256([14524762148725782528, 0, 0, 0])),
    AtcRational(Uint256([14522109841147760640, 0, 0, 0])),
    AtcRational(Uint256([14519427789388460032, 0, 0, 0])),
    AtcRational(Uint256([14516715671239366656, 0, 0, 0])),
    AtcRational(Uint256([14513973161261858816, 0, 0, 0])),
    AtcRational(Uint256([14511199930760869888, 0, 0, 0])),
    AtcRational(Uint256([14508395647758436352, 0, 0, 0])),
    AtcRational(Uint256([14505559976967245824, 0, 0, 0])),
    AtcRational(Uint256([14502692579764047872, 0, 0, 0])),
    AtcRational(Uint256([14499793114163054592, 0, 0, 0])),
    AtcRational(Uint256([14496861234789287936, 0, 0, 0])),
    AtcRational(Uint256([14493896592851855360, 0, 0, 0])),
    AtcRational(Uint256([14490898836117196800, 0, 0, 0])),
    AtcRational(Uint256([14487867608882292736, 0, 0, 0])),
    AtcRational(Uint256([14484802551947833344, 0, 0, 0])),
    AtcRational(Uint256([14481703302591363072, 0, 0, 0])),
    AtcRational(Uint256([14478569494540392448, 0, 0, 0])),
    AtcRational(Uint256([14475400757945503744, 0, 0, 0])),
    AtcRational(Uint256([14472196719353440256, 0, 0, 0])),
    AtcRational(Uint256([14468957001680179200, 0, 0, 0])),
    AtcRational(Uint256([14465681224184016896, 0, 0, 0])),
    AtcRational(Uint256([14462369002438653952, 0, 0, 0])),
    AtcRational(Uint256([14459019948306282496, 0, 0, 0])),
    AtcRational(Uint256([14455633669910710272, 0, 0, 0])),
    AtcRational(Uint256([14452209771610484736, 0, 0, 0])),
    AtcRational(Uint256([14448747853972076544, 0, 0, 0])),
    AtcRational(Uint256([14445247513743073280, 0, 0, 0])),
    AtcRational(Uint256([14441708343825438720, 0, 0, 0])),
    AtcRational(Uint256([14438129933248808960, 0, 0, 0])),
    AtcRational(Uint256([14434511867143868416, 0, 0, 0])),
    AtcRational(Uint256([14430853726715774976, 0, 0, 0])),
    AtcRational(Uint256([14427155089217667072, 0, 0, 0])),
    AtcRational(Uint256([14423415527924258816, 0, 0, 0])),
    AtcRational(Uint256([14419634612105521152, 0, 0, 0])),
    AtcRational(Uint256([14415811907000477696, 0, 0, 0])),
    AtcRational(Uint256([14411946973791092736, 0, 0, 0])),
    AtcRational(Uint256([14408039369576282112, 0, 0, 0])),
    AtcRational(Uint256([14404088647346073600, 0, 0, 0])),
    AtcRational(Uint256([14400094355955869696, 0, 0, 0])),
    AtcRational(Uint256([14396056040100884480, 0, 0, 0])),
    AtcRational(Uint256([14391973240290742272, 0, 0, 0])),
    AtcRational(Uint256([14387845492824211456, 0, 0, 0])),
    AtcRational(Uint256([14383672329764151296, 0, 0, 0])),
    AtcRational(Uint256([14379453278912624640, 0, 0, 0])),
    AtcRational(Uint256([14375187863786246144, 0, 0, 0])),
    AtcRational(Uint256([14370875603591677952, 0, 0, 0])),
    AtcRational(Uint256([14366516013201418240, 0, 0, 0])),
    AtcRational(Uint256([14362108603129778176, 0, 0, 0])),
    AtcRational(Uint256([14357652879509125120, 0, 0, 0])),
    AtcRational(Uint256([14353148344066387968, 0, 0, 0])),
    AtcRational(Uint256([14348594494099806208, 0, 0, 0])),
    AtcRational(Uint256([14343990822456012800, 0, 0, 0])),
    AtcRational(Uint256([14339336817507360768, 0, 0, 0])),
    AtcRational(Uint256([14334631963129606144, 0, 0, 0])),
    AtcRational(Uint256([14329875738679891968, 0, 0, 0])),
    AtcRational(Uint256([14325067618975068160, 0, 0, 0])),
    AtcRational(Uint256([14320207074270386176, 0, 0, 0])),
    AtcRational(Uint256([14315293570238543872, 0, 0, 0])),
    AtcRational(Uint256([14310326567949113344, 0, 0, 0])),
    AtcRational(Uint256([14305305523848388608, 0, 0, 0])),
    AtcRational(Uint256([14300229889739610112, 0, 0, 0])),
    AtcRational(Uint256([14295099112763666432, 0, 0, 0])),
    AtcRational(Uint256([14289912635380201472, 0, 0, 0])),
    AtcRational(Uint256([14284669895349196800, 0, 0, 0])),
    AtcRational(Uint256([14279370325713045504, 0, 0, 0])),
    AtcRational(Uint256([14274013354779123712, 0, 0, 0])),
    AtcRational(Uint256([14268598406102849536, 0, 0, 0])),
    AtcRational(Uint256([14263124898471307264, 0, 0, 0])),
    AtcRational(Uint256([14257592245887395840, 0, 0, 0])),
    AtcRational(Uint256([14251999857554575360, 0, 0, 0])),
    AtcRational(Uint256([14246347137862176768, 0, 0, 0])),
    AtcRational(Uint256([14240633486371330048, 0, 0, 0])),
    AtcRational(Uint256([14234858297801515008, 0, 0, 0])),
    AtcRational(Uint256([14229020962017785856, 0, 0, 0])),
    AtcRational(Uint256([14223120864018599936, 0, 0, 0])),
    AtcRational(Uint256([14217157383924420608, 0, 0, 0])),
    AtcRational(Uint256([14211129896966959104, 0, 0, 0])),
    AtcRational(Uint256([14205037773479176192, 0, 0, 0])),
    AtcRational(Uint256([14198880378886055936, 0, 0, 0])),
    AtcRational(Uint256([14192657073696112640, 0, 0, 0])),
    AtcRational(Uint256([14186367213493727232, 0, 0, 0])),
    AtcRational(Uint256([14180010148932296704, 0, 0, 0])),
    AtcRational(Uint256([14173585225728227328, 0, 0, 0])),
    AtcRational(Uint256([14167091784655794176, 0, 0, 0])),
    AtcRational(Uint256([14160529161542889472, 0, 0, 0])),
    AtcRational(Uint256([14153896687267710976, 0, 0, 0])),
    AtcRational(Uint256([14147193687756355584, 0, 0, 0])),
    AtcRational(Uint256([14140419483981410304, 0, 0, 0])),
    AtcRational(Uint256([14133573391961522176, 0, 0, 0])),
    AtcRational(Uint256([14126654722761990144, 0, 0, 0])),
    AtcRational(Uint256([14119662782496409600, 0, 0, 0])),
    AtcRational(Uint256([14112596872329363456, 0, 0, 0])),
    AtcRational(Uint256([14105456288480262144, 0, 0, 0])),
    AtcRational(Uint256([14098240322228244480, 0, 0, 0])),
    AtcRational(Uint256([14090948259918305280, 0, 0, 0])),
    AtcRational(Uint256([14083579382968543232, 0, 0, 0])),
    AtcRational(Uint256([14076132967878658048, 0, 0, 0])),
    AtcRational(Uint256([14068608286239690752, 0, 0, 0])),
    AtcRational(Uint256([14061004604745011200, 0, 0, 0])),
    AtcRational(Uint256([14053321185202620416, 0, 0, 0])),
    AtcRational(Uint256([14045557284548792320, 0, 0, 0])),
    AtcRational(Uint256([14037712154863056896, 0, 0, 0])),
    AtcRational(Uint256([14029785043384606720, 0, 0, 0])),
    AtcRational(Uint256([14021775192530079744, 0, 0, 0])),
    AtcRational(Uint256([14013681839912861696, 0, 0, 0])),
    AtcRational(Uint256([14005504218363817984, 0, 0, 0])),
    AtcRational(Uint256([13997241555953580032, 0, 0, 0])),
    AtcRational(Uint256([13988893076016375808, 0, 0, 0])),
    AtcRational(Uint256([13980457997175449600, 0, 0, 0])),
    AtcRational(Uint256([13971935533370089472, 0, 0, 0])),
    AtcRational(Uint256([13963324893884334080, 0, 0, 0])),
    AtcRational(Uint256([13954625283377340416, 0, 0, 0])),
    AtcRational(Uint256([13945835901915490304, 0, 0, 0])),
    AtcRational(Uint256([13936955945006243840, 0, 0, 0])),
    AtcRational(Uint256([13927984603633807360, 0, 0, 0])),
    AtcRational(Uint256([13918921064296585216, 0, 0, 0])),
    AtcRational(Uint256([13909764509046546432, 0, 0, 0])),
    AtcRational(Uint256([13900514115530459136, 0, 0, 0])),
    AtcRational(Uint256([13891169057033058304, 0, 0, 0])),
    AtcRational(Uint256([13881728502522195968, 0, 0, 0])),
    AtcRational(Uint256([13872191616696016896, 0, 0, 0])),
    AtcRational(Uint256([13862557560032120832, 0, 0, 0])),
    AtcRational(Uint256([13852825488838891520, 0, 0, 0])),
    AtcRational(Uint256([13842994555308853248, 0, 0, 0])),
    AtcRational(Uint256([13833063907574269952, 0, 0, 0])),
    AtcRational(Uint256([13823032689764870144, 0, 0, 0])),
    AtcRational(Uint256([13812900042067845120, 0, 0, 0])),
    AtcRational(Uint256([13802665100790099968, 0, 0, 0])),
    AtcRational(Uint256([13792326998422816768, 0, 0, 0])),
    AtcRational(Uint256([13781884863708366848, 0, 0, 0])),
    AtcRational(Uint256([13771337821709592576, 0, 0, 0])),
    AtcRational(Uint256([13760684993881540608, 0, 0, 0])),
    AtcRational(Uint256([13749925498145615872, 0, 0, 0])),
    AtcRational(Uint256([13739058448966279168, 0, 0, 0])),
    AtcRational(Uint256([13728082957430233088, 0, 0, 0])),
    AtcRational(Uint256([13716998131328233472, 0, 0, 0])),
    AtcRational(Uint256([13705803075239473152, 0, 0, 0])),
    AtcRational(Uint256([13694496890618648576, 0, 0, 0])),
    AtcRational(Uint256([13683078675885682688, 0, 0, 0])),
    AtcRational(Uint256([13671547526518214656, 0, 0, 0])),
    AtcRational(Uint256([13659902535146829824, 0, 0, 0])),
    AtcRational(Uint256([13648142791653093376, 0, 0, 0])),
    AtcRational(Uint256([13636267383270436864, 0, 0, 0])),
    AtcRational(Uint256([13624275394687913984, 0, 0, 0])),
    AtcRational(Uint256([13612165908156874752, 0, 0, 0])),
    AtcRational(Uint256([13599938003600584704, 0, 0, 0])),
    AtcRational(Uint256([13587590758726844416, 0, 0, 0])),
    AtcRational(Uint256([13575123249143625728, 0, 0, 0])),
    AtcRational(Uint256([13562534548477763584, 0, 0, 0])),
    AtcRational(Uint256([13549823728496742400, 0, 0, 0])),
    AtcRational(Uint256([13536989859233630208, 0, 0, 0])),
    AtcRational(Uint256([13524032009115150336, 0, 0, 0])),
    AtcRational(Uint256([13510949245092962304, 0, 0, 0])),
    AtcRational(Uint256([13497740632778186752, 0, 0, 0])),
    AtcRational(Uint256([13484405236579164160, 0, 0, 0])),
    AtcRational(Uint256([13470942119842529280, 0, 0, 0])),
    AtcRational(Uint256([13457350344997619712, 0, 0, 0])),
    AtcRational(Uint256([13443628973704206336, 0, 0, 0])),
    AtcRational(Uint256([13429777067003654144, 0, 0, 0])),
    AtcRational(Uint256([13415793685473462272, 0, 0, 0])),
    AtcRational(Uint256([13401677889385263104, 0, 0, 0])),
    AtcRational(Uint256([13387428738866302976, 0, 0, 0])),
    AtcRational(Uint256([13373045294064392192, 0, 0, 0])),
    AtcRational(Uint256([13358526615316400128, 0, 0, 0])),
    AtcRational(Uint256([13343871763320287232, 0, 0, 0])),
    AtcRational(Uint256([13329079799310704640, 0, 0, 0])),
    AtcRational(Uint256([13314149785238190080, 0, 0, 0])),
    AtcRational(Uint256([13299080783951974400, 0, 0, 0])),
    AtcRational(Uint256([13283871859386413056, 0, 0, 0])),
    AtcRational(Uint256([13268522076751075328, 0, 0, 0])),
    AtcRational(Uint256([13253030502724497408, 0, 0, 0])),
    AtcRational(Uint256([13237396205651617792, 0, 0, 0])),
    AtcRational(Uint256([13221618255744899072, 0, 0, 0])),
    AtcRational(Uint256([13205695725289166848, 0, 0, 0])),
    AtcRational(Uint256([13189627688850184192, 0, 0, 0])),
    AtcRational(Uint256([13173413223486908416, 0, 0, 0])),
    AtcRational(Uint256([13157051408967542784, 0, 0, 0])),
    AtcRational(Uint256([13140541327989270528, 0, 0, 0])),
    AtcRational(Uint256([13123882066401785856, 0, 0, 0])),
    AtcRational(Uint256([13107072713434537984, 0, 0, 0])),
    AtcRational(Uint256([13090112361927747584, 0, 0, 0])),
    AtcRational(Uint256([13073000108567144448, 0, 0, 0])),
    AtcRational(Uint256([13055735054122481664, 0, 0, 0])),
    AtcRational(Uint256([13038316303689742336, 0, 0, 0])),
    AtcRational(Uint256([13020742966937124864, 0, 0, 0])),
    AtcRational(Uint256([13003014158354718720, 0, 0, 0])),
    AtcRational(Uint256([12985128997507874816, 0, 0, 0])),
    AtcRational(Uint256([12967086609294301184, 0, 0, 0])),
    AtcRational(Uint256([12948886124204806144, 0, 0, 0])),
    AtcRational(Uint256([12930526678587715584, 0, 0, 0])),
    AtcRational(Uint256([12912007414916904960, 0, 0, 0])),
    AtcRational(Uint256([12893327482063446016, 0, 0, 0])),
    AtcRational(Uint256([12874486035570843648, 0, 0, 0])),
    AtcRational(Uint256([12855482237933809664, 0, 0, 0])),
    AtcRational(Uint256([12836315258880561152, 0, 0, 0])),
    AtcRational(Uint256([12816984275658594304, 0, 0, 0])),
    AtcRational(Uint256([12797488473323913216, 0, 0, 0])),
    AtcRational(Uint256([12777827045033641984, 0, 0, 0])),
    AtcRational(Uint256([12757999192342022144, 0, 0, 0])),
    AtcRational(Uint256([12738004125499680768, 0, 0, 0])),
    AtcRational(Uint256([12717841063756201984, 0, 0, 0])),
    AtcRational(Uint256([12697509235665854464, 0, 0, 0])),
    AtcRational(Uint256([12677007879396530176, 0, 0, 0])),
    AtcRational(Uint256([12656336243041691648, 0, 0, 0])),
    AtcRational(Uint256([12635493584935419904, 0, 0, 0])),
    AtcRational(Uint256([12614479173970364416, 0, 0, 0])),
    AtcRational(Uint256([12593292289918617600, 0, 0, 0])),
    AtcRational(Uint256([12571932223755370496, 0, 0, 0])),
    AtcRational(Uint256([12550398277985329152, 0, 0, 0])),
    AtcRational(Uint256([12528689766971766784, 0, 0, 0])),
    AtcRational(Uint256([12506806017268160512, 0, 0, 0])),
    AtcRational(Uint256([12484746367952306176, 0, 0, 0])),
    AtcRational(Uint256([12462510170962810880, 0, 0, 0])),
    AtcRational(Uint256([12440096791437899776, 0, 0, 0])),
    AtcRational(Uint256([12417505608056395776, 0, 0, 0])),
    AtcRational(Uint256([12394736013380814848, 0, 0, 0])),
    AtcRational(Uint256([12371787414202433536, 0, 0, 0])),
    AtcRational(Uint256([12348659231888226304, 0, 0, 0])),
    AtcRational(Uint256([12325350902729566208, 0, 0, 0])),
    AtcRational(Uint256([12301861878292580352, 0, 0, 0])),
    AtcRational(Uint256([12278191625770014720, 0, 0, 0])),
    AtcRational(Uint256([12254339628334479360, 0, 0, 0])),
    AtcRational(Uint256([12230305385492973568, 0, 0, 0])),
    AtcRational(Uint256([12206088413442545664, 0, 0, 0])),
    AtcRational(Uint256([12181688245426927616, 0, 0, 0])),
    AtcRational(Uint256([12157104432094023680, 0, 0, 0])),
    AtcRational(Uint256([12132336541854107648, 0, 0, 0])),
    AtcRational(Uint256([12107384161238581248, 0, 0, 0])),
    AtcRational(Uint256([12082246895259109376, 0, 0, 0])),
    AtcRational(Uint256([12056924367767033856, 0, 0, 0])),
    AtcRational(Uint256([12031416221812840448, 0, 0, 0])),
    AtcRational(Uint256([12005722120005560320, 0, 0, 0])),
    AtcRational(Uint256([11979841744871907328, 0, 0, 0])),
    AtcRational(Uint256([11953774799215020032, 0, 0, 0])),
    AtcRational(Uint256([11927521006472566784, 0, 0, 0])),
    AtcRational(Uint256([11901080111074107392, 0, 0, 0])),
    AtcRational(Uint256([11874451878797459456, 0, 0, 0])),
    AtcRational(Uint256([11847636097123960832, 0, 0, 0])),
    AtcRational(Uint256([11820632575592335360, 0, 0, 0])),
    AtcRational(Uint256([11793441146151079936, 0, 0, 0])),
    AtcRational(Uint256([11766061663509092352, 0, 0, 0])),
    AtcRational(Uint256([11738494005484369920, 0, 0, 0])),
    AtcRational(Uint256([11710738073350592512, 0, 0, 0])),
    AtcRational(Uint256([11682793792181340160, 0, 0, 0])),
    AtcRational(Uint256([11654661111191783424, 0, 0, 0])),
    AtcRational(Uint256([11626340004077604864, 0, 0, 0])),
    AtcRational(Uint256([11597830469350934528, 0, 0, 0])),
    AtcRational(Uint256([11569132530673096704, 0, 0, 0])),
    AtcRational(Uint256([11540246237183952896, 0, 0, 0])),
    AtcRational(Uint256([11511171663827582976, 0, 0, 0])),
    AtcRational(Uint256([11481908911674114048, 0, 0, 0])),
    AtcRational(Uint256([11452458108237473792, 0, 0, 0])),
    AtcRational(Uint256([11422819407788793856, 0, 0, 0])),
    AtcRational(Uint256([11392992991665272832, 0, 0, 0])),
    AtcRational(Uint256([11362979068574269440, 0, 0, 0])),
    AtcRational(Uint256([11332777874892353536, 0, 0, 0])),
    AtcRational(Uint256([11302389674959124480, 0, 0, 0])),
    AtcRational(Uint256([11271814761365499904, 0, 0, 0])),
    AtcRational(Uint256([11241053455236325376, 0, 0, 0])),
    AtcRational(Uint256([11210106106506956800, 0, 0, 0])),
    AtcRational(Uint256([11178973094193678336, 0, 0, 0])),
    AtcRational(Uint256([11147654826657650688, 0, 0, 0])),
    AtcRational(Uint256([11116151741862152192, 0, 0, 0])),
    AtcRational(Uint256([11084464307622914048, 0, 0, 0])),
    AtcRational(Uint256([11052593021851269120, 0, 0, 0])),
    AtcRational(Uint256([11020538412789880832, 0, 0, 0])),
    AtcRational(Uint256([10988301039240828928, 0, 0, 0])),
    AtcRational(Uint256([10955881490785785856, 0, 0, 0])),
    AtcRational(Uint256([10923280387998085120, 0, 0, 0])),
    AtcRational(Uint256([10890498382646384640, 0, 0, 0])),
    AtcRational(Uint256([10857536157889769472, 0, 0, 0])),
    AtcRational(Uint256([10824394428463968256, 0, 0, 0])),
    AtcRational(Uint256([10791073940858529792, 0, 0, 0])),
    AtcRational(Uint256([10757575473484689408, 0, 0, 0])),
    AtcRational(Uint256([10723899836833691648, 0, 0, 0])),
    AtcRational(Uint256([10690047873625384960, 0, 0, 0])),
    AtcRational(Uint256([10656020458946807808, 0, 0, 0])),
    AtcRational(Uint256([10621818500380600320, 0, 0, 0])),
    AtcRational(Uint256([10587442938122995712, 0, 0, 0])),
    AtcRational(Uint256([10552894745091184640, 0, 0, 0])),
    AtcRational(Uint256([10518174927019845632, 0, 0, 0])),
    AtcRational(Uint256([10483284522546655232, 0, 0, 0])),
    AtcRational(Uint256([10448224603286523904, 0, 0, 0])),
    AtcRational(Uint256([10412996273894438912, 0, 0, 0])),
    AtcRational(Uint256([10377600672116664320, 0, 0, 0])),
    AtcRational(Uint256([10342038968830132224, 0, 0, 0])),
    AtcRational(Uint256([10306312368069857280, 0, 0, 0])),
    AtcRational(Uint256([10270422107044188160, 0, 0, 0])),
    AtcRational(Uint256([10234369456137705472, 0, 0, 0])),
    AtcRational(Uint256([10198155718901680128, 0, 0, 0])),
    AtcRational(Uint256([10161782232031832064, 0, 0, 0])),
    AtcRational(Uint256([10125250365333327872, 0, 0, 0])),
    AtcRational(Uint256([10088561521672830976, 0, 0, 0])),
    AtcRational(Uint256([10051717136917477376, 0, 0, 0])),
    AtcRational(Uint256([10014718679860666368, 0, 0, 0])),
    AtcRational(Uint256([9977567652134516736, 0, 0, 0])),
    AtcRational(Uint256([9940265588108912640, 0, 0, 0])),
    AtcRational(Uint256([9902814054777008128, 0, 0, 0])),
    AtcRational(Uint256([9865214651627091968, 0, 0, 0])),
    AtcRational(Uint256([9827469010500773888, 0, 0, 0])),
    AtcRational(Uint256([9789578795437342720, 0, 0, 0])),
    AtcRational(Uint256([9751545702504284160, 0, 0, 0])),
    AtcRational(Uint256([9713371459613874176, 0, 0, 0])),
    AtcRational(Uint256([9675057826325798912, 0, 0, 0])),
    AtcRational(Uint256([9636606593635780608, 0, 0, 0])),
    AtcRational(Uint256([9598019583750131712, 0, 0, 0])),
    AtcRational(Uint256([9559298649846272000, 0, 0, 0])),
    AtcRational(Uint256([9520445675819153408, 0, 0, 0])),
    AtcRational(Uint256([9481462576013621248, 0, 0, 0])),
    AtcRational(Uint256([9442351294942703616, 0, 0, 0])),
    AtcRational(Uint256([9403113806991841280, 0, 0, 0])),
    AtcRational(Uint256([9363752116109119488, 0, 0, 0])),
    AtcRational(Uint256([9324268255481511936, 0, 0, 0])),
    AtcRational(Uint256([9284664287197179904, 0, 0, 0])),
    AtcRational(Uint256([9244942301893949440, 0, 0, 0])),
    AtcRational(Uint256([9205104418393949184, 0, 0, 0])),
    AtcRational(Uint256([9165152783324563456, 0, 0, 0])),
    AtcRational(Uint256([9125089570725771264, 0, 0, 0])),
    AtcRational(Uint256([9084916981643961344, 0, 0, 0])),
    AtcRational(Uint256([9044637243712360448, 0, 0, 0])),
    AtcRational(Uint256([9004252610718200832, 0, 0, 0])),
    AtcRational(Uint256([8963765362156744704, 0, 0, 0])),
    AtcRational(Uint256([8923177802772338688, 0, 0, 0])),
    AtcRational(Uint256([8882492262086646784, 0, 0, 0])),
    AtcRational(Uint256([8841711093914219520, 0, 0, 0])),
    AtcRational(Uint256([8800836675865615360, 0, 0, 0])),
    AtcRational(Uint256([8759871408838231040, 0, 0, 0])),
    AtcRational(Uint256([8718817716495054848, 0, 0, 0])),
    AtcRational(Uint256([8677678044731567104, 0, 0, 0])),
    AtcRational(Uint256([8636454861130998784, 0, 0, 0])),
    AtcRational(Uint256([8595150654408180736, 0, 0, 0])),
    AtcRational(Uint256([8553767933842236416, 0, 0, 0])),
    AtcRational(Uint256([8512309228698363904, 0, 0, 0])),
    AtcRational(Uint256([8470777087638975488, 0, 0, 0])),
    AtcRational(Uint256([8429174078124461056, 0, 0, 0])),
    AtcRational(Uint256([8387502785803874304, 0, 0, 0])),
    AtcRational(Uint256([8345765813895795712, 0, 0, 0])),
    AtcRational(Uint256([8303965782559726592, 0, 0, 0])),
    AtcRational(Uint256([8262105328258275328, 0, 0, 0])),
    AtcRational(Uint256([8220187103110477824, 0, 0, 0])),
    AtcRational(Uint256([8178213774236573696, 0, 0, 0])),
    AtcRational(Uint256([8136188023094564864, 0, 0, 0])),
    AtcRational(Uint256([8094112544808916992, 0, 0, 0])),
    AtcRational(Uint256([8051990047491715072, 0, 0, 0])),
    AtcRational(Uint256([8009823251556677632, 0, 0, 0])),
    AtcRational(Uint256([7967614889026356224, 0, 0, 0])),
    AtcRational(Uint256([7925367702832887808, 0, 0, 0])),
    AtcRational(Uint256([7883084446112715776, 0, 0, 0])),
    AtcRational(Uint256([7840767881495595008, 0, 0, 0])),
    AtcRational(Uint256([7798420780388343808, 0, 0, 0])),
    AtcRational(Uint256([7756045922253651968, 0, 0, 0])),
    AtcRational(Uint256([7713646093884422144, 0, 0, 0])),
    AtcRational(Uint256([7671224088673970176, 0, 0, 0])),
    AtcRational(Uint256([7628782705882552320, 0, 0, 0])),
    AtcRational(Uint256([7586324749900575744, 0, 0, 0])),
    AtcRational(Uint256([7543853029508941824, 0, 0, 0])),
    AtcRational(Uint256([7501370357136906240, 0, 0, 0])),
    AtcRational(Uint256([7458879548117898240, 0, 0, 0])),
    AtcRational(Uint256([7416383419943693312, 0, 0, 0])),
    AtcRational(Uint256([7373884791517374464, 0, 0, 0])),
    AtcRational(Uint256([7331386482405493760, 0, 0, 0])),
    AtcRational(Uint256([7288891312089871360, 0, 0, 0])),
    AtcRational(Uint256([7246402099219427328, 0, 0, 0])),
    AtcRational(Uint256([7203921660862483456, 0, 0, 0])),
    AtcRational(Uint256([7161452811759982592, 0, 0, 0])),
    AtcRational(Uint256([7118998363579975680, 0, 0, 0])),
    AtcRational(Uint256([7076561124173879296, 0, 0, 0])),
    AtcRational(Uint256([7034143896834856960, 0, 0, 0])),
    AtcRational(Uint256([6991749479558778880, 0, 0, 0])),
    AtcRational(Uint256([6949380664308144128, 0, 0, 0])),
    AtcRational(Uint256([6907040236279402496, 0, 0, 0])),
    AtcRational(Uint256([6864730973174070272, 0, 0, 0])),
    AtcRational(Uint256([6822455644474029056, 0, 0, 0])),
    AtcRational(Uint256([6780217010721434624, 0, 0, 0])),
    AtcRational(Uint256([6738017822803616768, 0, 0, 0])),
    AtcRational(Uint256([6695860821243351040, 0, 0, 0])),
    AtcRational(Uint256([6653748735494901760, 0, 0, 0])),
    AtcRational(Uint256([6611684283246219264, 0, 0, 0])),
    AtcRational(Uint256([6569670169727631360, 0, 0, 0])),
    AtcRational(Uint256([6527709087027459072, 0, 0, 0])),
    AtcRational(Uint256([6485803713414843392, 0, 0, 0])),
    AtcRational(Uint256([6443956712670195712, 0, 0, 0])),
    AtcRational(Uint256([6402170733423590400, 0, 0, 0])),
    AtcRational(Uint256([6360448408501444608, 0, 0, 0])),
    AtcRational(Uint256([6318792354281820160, 0, 0, 0])),
    AtcRational(Uint256([6277205170058672128, 0, 0, 0])),
    AtcRational(Uint256([6235689437415347200, 0, 0, 0])),
    AtcRational(Uint256([6194247719607663616, 0, 0, 0])),
    AtcRational(Uint256([6152882560956841984, 0, 0, 0])),
    AtcRational(Uint256([6111596486252597248, 0, 0, 0])),
    AtcRational(Uint256([6070392000166668288, 0, 0, 0])),
    AtcRational(Uint256([6029271586677042176, 0, 0, 0])),
    AtcRational(Uint256([5988237708503158784, 0, 0, 0])),
    AtcRational(Uint256([5947292806552320000, 0, 0, 0])),
    AtcRational(Uint256([5906439299377565696, 0, 0, 0])),
    AtcRational(Uint256([5865679582647235584, 0, 0, 0])),
    AtcRational(Uint256([5825016028626446336, 0, 0, 0])),
    AtcRational(Uint256([5784450985670685696, 0, 0, 0])),
    AtcRational(Uint256([5743986777731734528, 0, 0, 0])),
    AtcRational(Uint256([5703625703876088832, 0, 0, 0])),
    AtcRational(Uint256([5663370037816086528, 0, 0, 0])),
    AtcRational(Uint256([5623222027453882368, 0, 0, 0])),
    AtcRational(Uint256([5583183894438436864, 0, 0, 0])),
    AtcRational(Uint256([5543257833735676928, 0, 0, 0])),
    AtcRational(Uint256([5503446013211941888, 0, 0, 0])),
    AtcRational(Uint256([5463750573230858240, 0, 0, 0])),
    AtcRational(Uint256([5424173626263745536, 0, 0, 0])),
    AtcRational(Uint256([5384717256513666048, 0, 0, 0])),
    AtcRational(Uint256([5345383519553192960, 0, 0, 0])),
    AtcRational(Uint256([5306174441976003584, 0, 0, 0])),
    AtcRational(Uint256([5267092021062338560, 0, 0, 0])),
    AtcRational(Uint256([5228138224458407936, 0, 0, 0])),
    AtcRational(Uint256([5189314989869789184, 0, 0, 0])),
    AtcRational(Uint256([5150624224768840704, 0, 0, 0])),
    AtcRational(Uint256([5112067806116179968, 0, 0, 0])),
    AtcRational(Uint256([5073647580096222208, 0, 0, 0])),
    AtcRational(Uint256([5035365361866804224, 0, 0, 0])),
    AtcRational(Uint256([4997222935322875904, 0, 0, 0])),
    AtcRational(Uint256([4959222052874251264, 0, 0, 0])),
    AtcRational(Uint256([4921364435237403648, 0, 0, 0])),
    AtcRational(Uint256([4883651771241251840, 0, 0, 0])),
    AtcRational(Uint256([4846085717646911488, 0, 0, 0])),
    AtcRational(Uint256([4808667898981359616, 0, 0, 0])),
    AtcRational(Uint256([4771399907384928256, 0, 0, 0])),
    AtcRational(Uint256([4734283302472590336, 0, 0, 0])),
    AtcRational(Uint256([4697319611208928256, 0, 0, 0])),
    AtcRational(Uint256([4660510327796715520, 0, 0, 0])),
    AtcRational(Uint256([4623856913578997760, 0, 0, 0])),
    AtcRational(Uint256([4587360796954596352, 0, 0, 0])),
    AtcRational(Uint256([4551023373306879488, 0, 0, 0])),
    AtcRational(Uint256([4514846004945721344, 0, 0, 0])),
    AtcRational(Uint256([4478830021062493696, 0, 0, 0])),
    AtcRational(Uint256([4442976717697962496, 0, 0, 0])),
    AtcRational(Uint256([4407287357722949632, 0, 0, 0])),
    AtcRational(Uint256([4371763170831599616, 0, 0, 0])),
    AtcRational(Uint256([4336405353547112960, 0, 0, 0])),
    AtcRational(Uint256([4301215069239754752, 0, 0, 0])),
    AtcRational(Uint256([4266193448156999680, 0, 0, 0])),
    AtcRational(Uint256([4231341587465614848, 0, 0, 0])),
    AtcRational(Uint256([4196660551305514496, 0, 0, 0])),
    AtcRational(Uint256([4162151370855192064, 0, 0, 0])),
    AtcRational(Uint256([4127815044408539136, 0, 0, 0])),
    AtcRational(Uint256([4093652537462862336, 0, 0, 0])),
    AtcRational(Uint256([4059664782817884160, 0, 0, 0])),
    AtcRational(Uint256([4025852680685536768, 0, 0, 0])),
    AtcRational(Uint256([3992217098810330624, 0, 0, 0])),
    AtcRational(Uint256([3958758872600086528, 0, 0, 0])),
    AtcRational(Uint256([3925478805266815488, 0, 0, 0])),
    AtcRational(Uint256([3892377667977526784, 0, 0, 0])),
    AtcRational(Uint256([3859456200014740992, 0, 0, 0])),
    AtcRational(Uint256([3826715108946479616, 0, 0, 0])),
    AtcRational(Uint256([3794155070805506048, 0, 0, 0])),
    AtcRational(Uint256([3761776730277590016, 0, 0, 0])),
    AtcRational(Uint256([3729580700898548736, 0, 0, 0])),
    AtcRational(Uint256([3697567565259854336, 0, 0, 0])),
    AtcRational(Uint256([3665737875222543872, 0, 0, 0])),
    AtcRational(Uint256([3634092152139219456, 0, 0, 0])),
    AtcRational(Uint256([3602630887083875840, 0, 0, 0])),
    AtcRational(Uint256([3571354541089344000, 0, 0, 0])),
    AtcRational(Uint256([3540263545392078336, 0, 0, 0])),
    AtcRational(Uint256([3509358301684075008, 0, 0, 0])),
    AtcRational(Uint256([3478639182371662336, 0, 0, 0])),
    AtcRational(Uint256([3448106530840935936, 0, 0, 0])),
    AtcRational(Uint256([3417760661729580032, 0, 0, 0])),
    AtcRational(Uint256([3387601861204853760, 0, 0, 0])),
    AtcRational(Uint256([3357630387247493120, 0, 0, 0])),
    AtcRational(Uint256([3327846469941282304, 0, 0, 0])),
    AtcRational(Uint256([3298250311768075776, 0, 0, 0])),
    AtcRational(Uint256([3268842087908014080, 0, 0, 0])),
    AtcRational(Uint256([3239621946544709632, 0, 0, 0])),
    AtcRational(Uint256([3210590009175161344, 0, 0, 0])),
    AtcRational(Uint256([3181746370924176384, 0, 0, 0])),
    AtcRational(Uint256([3153091100863047680, 0, 0, 0])),
    AtcRational(Uint256([3124624242332286464, 0, 0, 0])),
    AtcRational(Uint256([3096345813268148736, 0, 0, 0])),
    AtcRational(Uint256([3068255806532773376, 0, 0, 0])),
    AtcRational(Uint256([3040354190247658496, 0, 0, 0])),
    AtcRational(Uint256([3012640908130307584, 0, 0, 0])),
    AtcRational(Uint256([2985115879833786880, 0, 0, 0])),
    AtcRational(Uint256([2957779001289008640, 0, 0, 0])),
    AtcRational(Uint256([2930630145049504256, 0, 0, 0])),
    AtcRational(Uint256([2903669160638502400, 0, 0, 0])),
    AtcRational(Uint256([2876895874898083840, 0, 0, 0])),
    AtcRational(Uint256([2850310092340229632, 0, 0, 0])),
    AtcRational(Uint256([2823911595499543552, 0, 0, 0])),
    AtcRational(Uint256([2797700145287476736, 0, 0, 0])),
    AtcRational(Uint256([2771675481347832320, 0, 0, 0])),
    AtcRational(Uint256([2745837322413390848, 0, 0, 0])),
    AtcRational(Uint256([2720185366663441408, 0, 0, 0])),
    AtcRational(Uint256([2694719292082065408, 0, 0, 0])),
    AtcRational(Uint256([2669438756816964096, 0, 0, 0])),
    AtcRational(Uint256([2644343399538680832, 0, 0, 0])),
    AtcRational(Uint256([2619432839800029696, 0, 0, 0])),
    AtcRational(Uint256([2594706678395571200, 0, 0, 0])),
    AtcRational(Uint256([2570164497720961536, 0, 0, 0])),
    AtcRational(Uint256([2545805862132034048, 0, 0, 0])),
    AtcRational(Uint256([2521630318303431168, 0, 0, 0])),
    AtcRational(Uint256([2497637395586657792, 0, 0, 0])),
    AtcRational(Uint256([2473826606367389696, 0, 0, 0])),
    AtcRational(Uint256([2450197446421903360, 0, 0, 0])),
    AtcRational(Uint256([2426749395272486912, 0, 0, 0])),
    AtcRational(Uint256([2403481916541677568, 0, 0, 0])),
    AtcRational(Uint256([2380394458305224704, 0, 0, 0])),
    AtcRational(Uint256([2357486453443613696, 0, 0, 0])),
    AtcRational(Uint256([2334757319992054272, 0, 0, 0])),
    AtcRational(Uint256([2312206461488791552, 0, 0, 0])),
    AtcRational(Uint256([2289833267321639936, 0, 0, 0])),
    AtcRational(Uint256([2267637113072605440, 0, 0, 0])),
    AtcRational(Uint256([2245617360860510720, 0, 0, 0])),
    AtcRational(Uint256([2223773359681494528, 0, 0, 0])),
    AtcRational(Uint256([2202104445747299072, 0, 0, 0])),
    AtcRational(Uint256([2180609942821237760, 0, 0, 0])),
    AtcRational(Uint256([2159289162551755520, 0, 0, 0])),
    AtcRational(Uint256([2138141404803482112, 0, 0, 0])),
    AtcRational(Uint256([2117165957985701120, 0, 0, 0])),
    AtcRational(Uint256([2096362099378140928, 0, 0, 0])),
    AtcRational(Uint256([2075729095454018048, 0, 0, 0])),
    AtcRational(Uint256([2055266202200243968, 0, 0, 0])),
    AtcRational(Uint256([2034972665434736128, 0, 0, 0])),
    AtcRational(Uint256([2014847721120749056, 0, 0, 0])),
    AtcRational(Uint256([1994890595678173952, 0, 0, 0])),
    AtcRational(Uint256([1975100506291729152, 0, 0, 0])),
    AtcRational(Uint256([1955476661215996672, 0, 0, 0])),
    AtcRational(Uint256([1936018260077233664, 0, 0, 0])),
    AtcRational(Uint256([1916724494171921152, 0, 0, 0])),
    AtcRational(Uint256([1897594546761984256, 0, 0, 0])),
    AtcRational(Uint256([1878627593366651904, 0, 0, 0])),
    AtcRational(Uint256([1859822802050898432, 0, 0, 0])),
    AtcRational(Uint256([1841179333710439168, 0, 0, 0])),
    AtcRational(Uint256([1822696342353232640, 0, 0, 0])),
    AtcRational(Uint256([1804372975377456640, 0, 0, 0])),
    AtcRational(Uint256([1786208373845930240, 0, 0, 0])),
    AtcRational(Uint256([1768201672756947200, 0, 0, 0])),
    AtcRational(Uint256([1750352001311492352, 0, 0, 0])),
    AtcRational(Uint256([1732658483176829696, 0, 0, 0])),
    AtcRational(Uint256([1715120236746417152, 0, 0, 0])),
    AtcRational(Uint256([1697736375396155136, 0, 0, 0])),
    AtcRational(Uint256([1680506007736934400, 0, 0, 0])),
    AtcRational(Uint256([1663428237863474432, 0, 0, 0])),
    AtcRational(Uint256([1646502165599439872, 0, 0, 0])),
    AtcRational(Uint256([1629726886738828032, 0, 0, 0])),
    AtcRational(Uint256([1613101493283616512, 0, 0, 0])),
    AtcRational(Uint256([1596625073677668096, 0, 0, 0])),
    AtcRational(Uint256([1580296713036883968, 0, 0, 0])),
    AtcRational(Uint256([1564115493375614976, 0, 0, 0])),
    AtcRational(Uint256([1548080493829320192, 0, 0, 0])),
    AtcRational(Uint256([1532190790873484288, 0, 0, 0])),
    AtcRational(Uint256([1516445458538788608, 0, 0, 0])),
    AtcRational(Uint256([1500843568622554368, 0, 0, 0])),
    AtcRational(Uint256([1485384190896454656, 0, 0, 0])),
    AtcRational(Uint256([1470066393310513152, 0, 0, 0])),
    AtcRational(Uint256([1454889242193393664, 0, 0, 0])),
    AtcRational(Uint256([1439851802449000192, 0, 0, 0])),
    AtcRational(Uint256([1424953137749395968, 0, 0, 0])),
    AtcRational(Uint256([1410192310724064000, 0, 0, 0])),
    AtcRational(Uint256([1395568383145516288, 0, 0, 0])),
    AtcRational(Uint256([1381080416111280128, 0, 0, 0])),
    AtcRational(Uint256([1366727470222276864, 0, 0, 0])),
    AtcRational(Uint256([1352508605757614592, 0, 0, 0])),
    AtcRational(Uint256([1338422882845812992, 0, 0, 0])),
    AtcRational(Uint256([1324469361632493312, 0, 0, 0])),
    AtcRational(Uint256([1310647102444549376, 0, 0, 0])),
    AtcRational(Uint256([1296955165950824704, 0, 0, 0])),
    AtcRational(Uint256([1283392613319330816, 0, 0, 0])),
    AtcRational(Uint256([1269958506371023872, 0, 0, 0])),
    AtcRational(Uint256([1256651907730177536, 0, 0, 0])),
    AtcRational(Uint256([1243471880971367936, 0, 0, 0])),
    AtcRational(Uint256([1230417490763117312, 0, 0, 0])),
    AtcRational(Uint256([1217487803008212736, 0, 0, 0])),
    AtcRational(Uint256([1204681884980741632, 0, 0, 0])),
    AtcRational(Uint256([1191998805459865088, 0, 0, 0])),
    AtcRational(Uint256([1179437634860375808, 0, 0, 0])),
    AtcRational(Uint256([1166997445360058880, 0, 0, 0])),
    AtcRational(Uint256([1154677311023903744, 0, 0, 0])),
    AtcRational(Uint256([1142476307925186944, 0, 0, 0])),
    AtcRational(Uint256([1130393514263474816, 0, 0, 0])),
    AtcRational(Uint256([1118428010479570176, 0, 0, 0])),
    AtcRational(Uint256([1106578879367446784, 0, 0, 0])),
    AtcRational(Uint256([1094845206183200000, 0, 0, 0])),
    AtcRational(Uint256([1083226078751057536, 0, 0, 0])),
    AtcRational(Uint256([1071720587566481536, 0, 0, 0])),
    AtcRational(Uint256([1060327825896404608, 0, 0, 0])),
    AtcRational(Uint256([1049046889876627200, 0, 0, 0])),
    AtcRational(Uint256([1037876878606426112, 0, 0, 0])),
    AtcRational(Uint256([1026816894240403456, 0, 0, 0])),
    AtcRational(Uint256([1015866042077617536, 0, 0, 0])),
    AtcRational(Uint256([1005023430648028800, 0, 0, 0])),
    AtcRational(Uint256([994288171796307968, 0, 0, 0])),
    AtcRational(Uint256([983659380763034624, 0, 0, 0])),
    AtcRational(Uint256([973136176263332992, 0, 0, 0])),
    AtcRational(Uint256([962717680562974336, 0, 0, 0])),
    AtcRational(Uint256([952403019551993984, 0, 0, 0])),
    AtcRational(Uint256([942191322815853056, 0, 0, 0])),
    AtcRational(Uint256([932081723704189696, 0, 0, 0])),
    AtcRational(Uint256([922073359397190528, 0, 0, 0])),
    AtcRational(Uint256([912165370969629056, 0, 0, 0])),
    AtcRational(Uint256([902356903452603136, 0, 0, 0])),
    AtcRational(Uint256([892647105893010176, 0, 0, 0])),
    AtcRational(Uint256([883035131410800384, 0, 0, 0])),
    AtcRational(Uint256([873520137254044800, 0, 0, 0])),
    AtcRational(Uint256([864101284851852928, 0, 0, 0])),
    AtcRational(Uint256([854777739865181312, 0, 0, 0])),
    AtcRational(Uint256([845548672235568384, 0, 0, 0])),
    AtcRational(Uint256([836413256231831552, 0, 0, 0])),
    AtcRational(Uint256([827370670494766720, 0, 0, 0])),
    AtcRational(Uint256([818420098079881728, 0, 0, 0])),
    AtcRational(Uint256([809560726498204800, 0, 0, 0])),
    AtcRational(Uint256([800791747755200896, 0, 0, 0])),
    AtcRational(Uint256([792112358387835392, 0, 0, 0])),
    AtcRational(Uint256([783521759499814016, 0, 0, 0])),
    AtcRational(Uint256([775019156795042816, 0, 0, 0])),
    AtcRational(Uint256([766603760609335424, 0, 0, 0])),
    AtcRational(Uint256([758274785940408960, 0, 0, 0])),
    AtcRational(Uint256([750031452476196608, 0, 0, 0])),
    AtcRational(Uint256([741872984621515008, 0, 0, 0])),
    AtcRational(Uint256([733798611523120256, 0, 0, 0])),
    AtcRational(Uint256([725807567093184512, 0, 0, 0])),
    AtcRational(Uint256([717899090031224448, 0, 0, 0])),
    AtcRational(Uint256([710072423844518784, 0, 0, 0])),
    AtcRational(Uint256([702326816867043968, 0, 0, 0])),
    AtcRational(Uint256([694661522276962432, 0, 0, 0])),
    AtcRational(Uint256([687075798112689920, 0, 0, 0])),
    AtcRational(Uint256([679568907287580672, 0, 0, 0])),
    AtcRational(Uint256([672140117603256192, 0, 0, 0])),
    AtcRational(Uint256([664788701761609984, 0, 0, 0])),
    AtcRational(Uint256([657513937375516800, 0, 0, 0])),
    AtcRational(Uint256([650315106978278272, 0, 0, 0])),
    AtcRational(Uint256([643191498031836288, 0, 0, 0])),
    AtcRational(Uint256([636142402933774464, 0, 0, 0])),
    AtcRational(Uint256([629167119023148800, 0, 0, 0])),
    AtcRational(Uint256([622264948585165440, 0, 0, 0])),
    AtcRational(Uint256([615435198854739840, 0, 0, 0])),
    AtcRational(Uint256([608677182018960512, 0, 0, 0])),
    AtcRational(Uint256([601990215218487424, 0, 0, 0])),
    AtcRational(Uint256([595373620547912192, 0, 0, 0])),
    AtcRational(Uint256([588826725055103488, 0, 0, 0])),
    AtcRational(Uint256([582348860739565568, 0, 0, 0])),
    AtcRational(Uint256([575939364549835840, 0, 0, 0])),
    AtcRational(Uint256([569597578379946176, 0, 0, 0])),
    AtcRational(Uint256([563322849064973184, 0, 0, 0])),
    AtcRational(Uint256([557114528375699392, 0, 0, 0])),
    AtcRational(Uint256([550971973012414144, 0, 0, 0])),
    AtcRational(Uint256([544894544597873792, 0, 0, 0])),
    AtcRational(Uint256([538881609669446912, 0, 0, 0])),
    AtcRational(Uint256([532932539670464960, 0, 0, 0])),
    AtcRational(Uint256([527046710940803776, 0, 0, 0])),
    AtcRational(Uint256([521223504706716480, 0, 0, 0])),
    AtcRational(Uint256([515462307069940352, 0, 0, 0])),
    AtcRational(Uint256([509762508996097024, 0, 0, 0])),
    AtcRational(Uint256([504123506302410304, 0, 0, 0])),
    AtcRational(Uint256([498544699644759936, 0, 0, 0])),
    AtcRational(Uint256([493025494504093248, 0, 0, 0])),
    AtcRational(Uint256([487565301172211520, 0, 0, 0])),
    AtcRational(Uint256([482163534736955520, 0, 0, 0])),
    AtcRational(Uint256([476819615066805056, 0, 0, 0])),
    AtcRational(Uint256([471532966794915008, 0, 0, 0])),
    AtcRational(Uint256([466303019302601600, 0, 0, 0])),
    AtcRational(Uint256([461129206702303360, 0, 0, 0])),
    AtcRational(Uint256([456010967820029760, 0, 0, 0])),
    AtcRational(Uint256([450947746177316224, 0, 0, 0])),
    AtcRational(Uint256([445938989972704576, 0, 0, 0])),
    AtcRational(Uint256([440984152062762688, 0, 0, 0])),
    AtcRational(Uint256([436082689942662912, 0, 0, 0])),
    AtcRational(Uint256([431234065726332992, 0, 0, 0])),
    AtcRational(Uint256([426437746126196672, 0, 0, 0])),
    AtcRational(Uint256([421693202432519040, 0, 0, 0])),
    AtcRational(Uint256([416999910492373440, 0, 0, 0])),
    AtcRational(Uint256([412357350688240704, 0, 0, 0])),
    AtcRational(Uint256([407765007916260352, 0, 0, 0])),
    AtcRational(Uint256([403222371564144896, 0, 0, 0])),
    AtcRational(Uint256([398728935488772800, 0, 0, 0])),
    AtcRational(Uint256([394284197993471488, 0, 0, 0])),
    AtcRational(Uint256([389887661805007040, 0, 0, 0])),
    AtcRational(Uint256([385538834050291776, 0, 0, 0])),
    AtcRational(Uint256([381237226232822592, 0, 0, 0])),
    AtcRational(Uint256([376982354208862784, 0, 0, 0])),
    AtcRational(Uint256([372773738163379840, 0, 0, 0])),
    AtcRational(Uint256([368610902585751744, 0, 0, 0])),
    AtcRational(Uint256([364493376245252288, 0, 0, 0])),
    AtcRational(Uint256([360420692166327168, 0, 0, 0])),
    AtcRational(Uint256([356392387603673216, 0, 0, 0])),
    AtcRational(Uint256([352408004017130240, 0, 0, 0])),
    AtcRational(Uint256([348467087046397696, 0, 0, 0])),
    AtcRational(Uint256([344569186485583936, 0, 0, 0])),
    AtcRational(Uint256([340713856257602176, 0, 0, 0])),
    AtcRational(Uint256([336900654388419392, 0, 0, 0])),
    AtcRational(Uint256([333129142981170944, 0, 0, 0])),
    AtcRational(Uint256([329398888190146944, 0, 0, 0])),
    AtcRational(Uint256([325709460194663424, 0, 0, 0])),
    AtcRational(Uint256([322060433172825088, 0, 0, 0])),
    AtcRational(Uint256([318451385275187776, 0, 0, 0])),
    AtcRational(Uint256([314881898598331776, 0, 0, 0])),
    AtcRational(Uint256([311351559158351808, 0, 0, 0])),
    AtcRational(Uint256([307859956864274048, 0, 0, 0])),
    AtcRational(Uint256([304406685491404992, 0, 0, 0])),
    AtcRational(Uint256([300991342654624192, 0, 0, 0])),
    AtcRational(Uint256([297613529781624320, 0, 0, 0])),
    AtcRational(Uint256([294272852086108864, 0, 0, 0])),
    AtcRational(Uint256([290968918540952256, 0, 0, 0])),
    AtcRational(Uint256([287701341851331328, 0, 0, 0])),
    AtcRational(Uint256([284469738427833696, 0, 0, 0])),
    AtcRational(Uint256([281273728359550304, 0, 0, 0])),
    AtcRational(Uint256([278112935387157216, 0, 0, 0])),
    AtcRational(Uint256([274986986875995200, 0, 0, 0])),
    AtcRational(Uint256([271895513789150592, 0, 0, 0])),
    AtcRational(Uint256([268838150660545664, 0, 0, 0])),
    AtcRational(Uint256([265814535568041440, 0, 0, 0])),
    AtcRational(Uint256([262824310106561728, 0, 0, 0])),
    AtcRational(Uint256([259867119361241024, 0, 0, 0])),
    AtcRational(Uint256([256942611880603296, 0, 0, 0])),
    AtcRational(Uint256([254050439649774752, 0, 0, 0])),
    AtcRational(Uint256([251190258063738688, 0, 0, 0])),
    AtcRational(Uint256([248361725900633600, 0, 0, 0])),
    AtcRational(Uint256([245564505295100640, 0, 0, 0])),
    AtcRational(Uint256([242798261711686880, 0, 0, 0])),
    AtcRational(Uint256([240062663918305152, 0, 0, 0])),
    AtcRational(Uint256([237357383959756160, 0, 0, 0])),
    AtcRational(Uint256([234682097131319296, 0, 0, 0])),
    AtcRational(Uint256([232036481952410816, 0, 0, 0])),
    AtcRational(Uint256([229420220140319360, 0, 0, 0])),
    AtcRational(Uint256([226832996584017152, 0, 0, 0])),
    AtcRational(Uint256([224274499318053024, 0, 0, 0])),
    AtcRational(Uint256([221744419496531680, 0, 0, 0])),
    AtcRational(Uint256([219242451367179744, 0, 0, 0])),
    AtcRational(Uint256([216768292245502976, 0, 0, 0])),
    AtcRational(Uint256([214321642489039520, 0, 0, 0])),
    AtcRational(Uint256([211902205471709248, 0, 0, 0])),
    AtcRational(Uint256([209509687558263072, 0, 0, 0])),
    AtcRational(Uint256([207143798078836928, 0, 0, 0])),
    AtcRational(Uint256([204804249303609280, 0, 0, 0])),
    AtcRational(Uint256([202490756417568736, 0, 0, 0])),
    AtcRational(Uint256([200203037495391232, 0, 0, 0])),
    AtcRational(Uint256([197940813476429664, 0, 0, 0])),
    AtcRational(Uint256([195703808139820608, 0, 0, 0])),
    AtcRational(Uint256([193491748079706688, 0, 0, 0])),
    AtcRational(Uint256([191304362680578688, 0, 0, 0])),
    AtcRational(Uint256([189141384092740352, 0, 0, 0])),
    AtcRational(Uint256([187002547207894304, 0, 0, 0])),
    AtcRational(Uint256([184887589634855776, 0, 0, 0])),
    AtcRational(Uint256([182796251675390752, 0, 0, 0])),
    AtcRational(Uint256([180728276300183808, 0, 0, 0])),
    AtcRational(Uint256([178683409124936320, 0, 0, 0])),
    AtcRational(Uint256([176661398386595648, 0, 0, 0])),
    AtcRational(Uint256([174661994919716768, 0, 0, 0])),
    AtcRational(Uint256([172684952132960128, 0, 0, 0])),
    AtcRational(Uint256([170730025985722752, 0, 0, 0])),
    AtcRational(Uint256([168796974964908128, 0, 0, 0])),
    AtcRational(Uint256([166885560061832896, 0, 0, 0])),
    AtcRational(Uint256([164995544749272480, 0, 0, 0])),
    AtcRational(Uint256([163126694958648032, 0, 0, 0])),
    AtcRational(Uint256([161278779057352736, 0, 0, 0])),
    AtcRational(Uint256([159451567826220640, 0, 0, 0])),
    AtcRational(Uint256([157644834437138816, 0, 0, 0])),
    AtcRational(Uint256([155858354430802016, 0, 0, 0])),
    AtcRational(Uint256([154091905694611360, 0, 0, 0])),
    AtcRational(Uint256([152345268440719328, 0, 0, 0])),
    AtcRational(Uint256([150618225184218048, 0, 0, 0])),
    AtcRational(Uint256([148910560721475488, 0, 0, 0])),
    AtcRational(Uint256([147222062108617056, 0, 0, 0])),
    AtcRational(Uint256([145552518640153856, 0, 0, 0])),
    AtcRational(Uint256([143901721827759536, 0, 0, 0])),
    AtcRational(Uint256([142269465379193696, 0, 0, 0])),
    AtcRational(Uint256([140655545177373184, 0, 0, 0])),
    AtcRational(Uint256([139059759259593184, 0, 0, 0])),
    AtcRational(Uint256([137481907796894496, 0, 0, 0])),
    AtcRational(Uint256([135921793073581792, 0, 0, 0])),
    AtcRational(Uint256([134379219466889200, 0, 0, 0])),
    AtcRational(Uint256([132853993426794880, 0, 0, 0])),
    AtcRational(Uint256([131345923455985760, 0, 0, 0])),
    AtcRational(Uint256([129854820089970032, 0, 0, 0])),
    AtcRational(Uint256([128380495877339056, 0, 0, 0])),
    AtcRational(Uint256([126922765360178944, 0, 0, 0])),
    AtcRational(Uint256([125481445054629696, 0, 0, 0])),
    AtcRational(Uint256([124056353431594704, 0, 0, 0])),
    AtcRational(Uint256([122647310897597840, 0, 0, 0])),
    AtcRational(Uint256([121254139775789056, 0, 0, 0])),
    AtcRational(Uint256([119876664287099296, 0, 0, 0])),
    AtcRational(Uint256([118514710531542512, 0, 0, 0])),
    AtcRational(Uint256([117168106469665536, 0, 0, 0])),
    AtcRational(Uint256([115836681904146544, 0, 0, 0])),
    AtcRational(Uint256([114520268461539280, 0, 0, 0])),
    AtcRational(Uint256([113218699574165632, 0, 0, 0])),
    AtcRational(Uint256([111931810462153952, 0, 0, 0])),
    AtcRational(Uint256([110659438115623328, 0, 0, 0])),
    AtcRational(Uint256([109401421277014816, 0, 0, 0])),
    AtcRational(Uint256([108157600423566912, 0, 0, 0])),
    AtcRational(Uint256([106927817749936160, 0, 0, 0])),
    AtcRational(Uint256([105711917150963008, 0, 0, 0])),
    AtcRational(Uint256([104509744204580720, 0, 0, 0])),
    AtcRational(Uint256([103321146154867984, 0, 0, 0])),
    AtcRational(Uint256([102145971895245168, 0, 0, 0])),
    AtcRational(Uint256([100984071951811872, 0, 0, 0])),
    AtcRational(Uint256([99835298466827488, 0, 0, 0])),
    AtcRational(Uint256([98699505182332368, 0, 0, 0])),
    AtcRational(Uint256([97576547423909568, 0, 0, 0])),
    AtcRational(Uint256([96466282084587616, 0, 0, 0])),
    AtcRational(Uint256([95368567608881936, 0, 0, 0])),
    AtcRational(Uint256([94283263976975168, 0, 0, 0])),
    AtcRational(Uint256([93210232689036528, 0, 0, 0])),
    AtcRational(Uint256([92149336749677664, 0, 0, 0])),
    AtcRational(Uint256([91100440652546432, 0, 0, 0])),
    AtcRational(Uint256([90063410365056304, 0, 0, 0])),
    AtcRational(Uint256([89038113313251152, 0, 0, 0])),
    AtcRational(Uint256([88024418366805744, 0, 0, 0])),
    AtcRational(Uint256([87022195824159632, 0, 0, 0])),
    AtcRational(Uint256([86031317397784352, 0, 0, 0])),
    AtcRational(Uint256([85051656199584336, 0, 0, 0])),
    AtcRational(Uint256([84083086726428336, 0, 0, 0])),
    AtcRational(Uint256([83125484845813488, 0, 0, 0])),
    AtcRational(Uint256([82178727781658848, 0, 0, 0])),
    AtcRational(Uint256([81242694100228816, 0, 0, 0])),
    AtcRational(Uint256([80317263696186016, 0, 0, 0])),
    AtcRational(Uint256([79402317778771824, 0, 0, 0])),
    AtcRational(Uint256([78497738858114176, 0, 0, 0])),
    AtcRational(Uint256([77603410731662624, 0, 0, 0])),
    AtcRational(Uint256([76719218470748448, 0, 0, 0])),
    AtcRational(Uint256([75845048407270416, 0, 0, 0])),
    AtcRational(Uint256([74980788120504400, 0, 0, 0])),
    AtcRational(Uint256([74126326424036208, 0, 0, 0])),
    AtcRational(Uint256([73281553352817728, 0, 0, 0])),
    AtcRational(Uint256([72446360150344240, 0, 0, 0])),
    AtcRational(Uint256([71620639255952600, 0, 0, 0])),
    AtcRational(Uint256([70804284292240360, 0, 0, 0])),
    AtcRational(Uint256([69997190052603488, 0, 0, 0])),
    AtcRational(Uint256([69199252488892648, 0, 0, 0])),
    AtcRational(Uint256([68410368699187752, 0, 0, 0])),
    AtcRational(Uint256([67630436915688592, 0, 0, 0])),
    AtcRational(Uint256([66859356492722160, 0, 0, 0])),
    AtcRational(Uint256([66097027894864808, 0, 0, 0])),
    AtcRational(Uint256([65343352685178616, 0, 0, 0])),
    AtcRational(Uint256([64598233513561880, 0, 0, 0])),
    AtcRational(Uint256([63861574105211760, 0, 0, 0])),
    AtcRational(Uint256([63133279249198800, 0, 0, 0])),
    AtcRational(Uint256([62413254787153008, 0, 0, 0])),
    AtcRational(Uint256([61701407602059336, 0, 0, 0])),
    AtcRational(Uint256([60997645607163304, 0, 0, 0])),
    AtcRational(Uint256([60301877734984648, 0, 0, 0])),
    AtcRational(Uint256([59614013926438576, 0, 0, 0])),
    AtcRational(Uint256([58933965120064440, 0, 0, 0])),
    AtcRational(Uint256([58261643241359936, 0, 0, 0])),
    AtcRational(Uint256([57596961192220440, 0, 0, 0])),
    AtcRational(Uint256([56939832840483304, 0, 0, 0])),
    AtcRational(Uint256([56290173009574848, 0, 0, 0])),
    AtcRational(Uint256([55647897468260864, 0, 0, 0])),
    AtcRational(Uint256([55012922920498480, 0, 0, 0])),
    AtcRational(Uint256([54385166995389032, 0, 0, 0])),
    AtcRational(Uint256([53764548237231728, 0, 0, 0])),
    AtcRational(Uint256([53150986095676152, 0, 0, 0])),
    AtcRational(Uint256([52544400915973480, 0, 0, 0])),
    AtcRational(Uint256([51944713929325792, 0, 0, 0])),
    AtcRational(Uint256([51351847243332064, 0, 0, 0])),
    AtcRational(Uint256([50765723832530176, 0, 0, 0])),
    AtcRational(Uint256([50186267529034840, 0, 0, 0])),
    AtcRational(Uint256([49613403013269352, 0, 0, 0])),
    AtcRational(Uint256([49047055804791736, 0, 0, 0])),
    AtcRational(Uint256([48487152253213424, 0, 0, 0])),
    AtcRational(Uint256([47933619529210104, 0, 0, 0])),
    AtcRational(Uint256([47386385615624248, 0, 0, 0])),
    AtcRational(Uint256([46845379298657936, 0, 0, 0])),
    AtcRational(Uint256([46310530159155312, 0, 0, 0])),
    AtcRational(Uint256([45781768563974600, 0, 0, 0])),
    AtcRational(Uint256([45259025657447672, 0, 0, 0])),
    AtcRational(Uint256([44742233352927632, 0, 0, 0])),
    AtcRational(Uint256([44231324324422752, 0, 0, 0])),
    AtcRational(Uint256([43726231998316280, 0, 0, 0])),
    AtcRational(Uint256([43226890545171720, 0, 0, 0])),
    AtcRational(Uint256([42733234871622224, 0, 0, 0])),
    AtcRational(Uint256([42245200612343560, 0, 0, 0])),
    AtcRational(Uint256([41762724122110312, 0, 0, 0])),
    AtcRational(Uint256([41285742467933752, 0, 0, 0])),
    AtcRational(Uint256([40814193421281544, 0, 0, 0])),
    AtcRational(Uint256([40348015450377768, 0, 0, 0])),
    AtcRational(Uint256([39887147712583024, 0, 0, 0])),
    AtcRational(Uint256([39431530046853688, 0, 0, 0])),
    AtcRational(Uint256([38981102966279480, 0, 0, 0])),
    AtcRational(Uint256([38535807650699128, 0, 0, 0])),
    AtcRational(Uint256([38095585939392688, 0, 0, 0])),
    AtcRational(Uint256([37660380323850216, 0, 0, 0])),
    AtcRational(Uint256([37230133940616360, 0, 0, 0])),
    AtcRational(Uint256([36804790564209328, 0, 0, 0])),
    AtcRational(Uint256([36384294600114552, 0, 0, 0])),
    AtcRational(Uint256([35968591077851516, 0, 0, 0])),
    AtcRational(Uint256([35557625644113388, 0, 0, 0])),
    AtcRational(Uint256([35151344555979076, 0, 0, 0])),
    AtcRational(Uint256([34749694674196404, 0, 0, 0])),
    AtcRational(Uint256([34352623456536068, 0, 0, 0])),
    AtcRational(Uint256([33960078951215948, 0, 0, 0])),
    AtcRational(Uint256([33572009790394584, 0, 0, 0])),
    AtcRational(Uint256([33188365183733360, 0, 0, 0])),
    AtcRational(Uint256([32809094912027156, 0, 0, 0])),
    AtcRational(Uint256([32434149320901908, 0, 0, 0])),
    AtcRational(Uint256([32063479314579508, 0, 0, 0])),
    AtcRational(Uint256([31697036349708460, 0, 0, 0])),
    AtcRational(Uint256([31334772429260116, 0, 0, 0])),
    AtcRational(Uint256([30976640096490016, 0, 0, 0])),
    AtcRational(Uint256([30622592428963244, 0, 0, 0])),
    AtcRational(Uint256([30272583032643336, 0, 0, 0])),
    AtcRational(Uint256([29926566036044560, 0, 0, 0])),
    AtcRational(Uint256([29584496084446084, 0, 0, 0])),
    AtcRational(Uint256([29246328334168376, 0, 0, 0])),
    AtcRational(Uint256([28912018446910460, 0, 0, 0])),
    AtcRational(Uint256([28581522584147772, 0, 0, 0])),
    AtcRational(Uint256([28254797401590164, 0, 0, 0])),
    AtcRational(Uint256([27931800043699132, 0, 0, 0])),
    AtcRational(Uint256([27612488138263732, 0, 0, 0])),
    AtcRational(Uint256([27296819791035000, 0, 0, 0])),
    AtcRational(Uint256([26984753580417632, 0, 0, 0])),
    AtcRational(Uint256([26676248552219052, 0, 0, 0])),
    AtcRational(Uint256([26371264214454720, 0, 0, 0])),
    AtcRational(Uint256([26069760532209384, 0, 0, 0])),
    AtcRational(Uint256([25771697922553848, 0, 0, 0])),
    AtcRational(Uint256([25477037249516400, 0, 0, 0])),
    AtcRational(Uint256([25185739819108396, 0, 0, 0])),
    AtcRational(Uint256([24897767374403864, 0, 0, 0])),
    AtcRational(Uint256([24613082090671888, 0, 0, 0])),
    AtcRational(Uint256([24331646570561924, 0, 0, 0])),
    AtcRational(Uint256([24053423839341064, 0, 0, 0])),
    AtcRational(Uint256([23778377340182780, 0, 0, 0])),
    AtcRational(Uint256([23506470929506944, 0, 0, 0])),
    AtcRational(Uint256([23237668872370196, 0, 0, 0])),
    AtcRational(Uint256([22971935837906256, 0, 0, 0])),
    AtcRational(Uint256([22709236894815996, 0, 0, 0])),
    AtcRational(Uint256([22449537506906248, 0, 0, 0])),
    AtcRational(Uint256([22192803528677148, 0, 0, 0])),
    AtcRational(Uint256([21939001200957664, 0, 0, 0])),
    AtcRational(Uint256([21688097146588316, 0, 0, 0])),
    AtcRational(Uint256([21440058366151208, 0, 0, 0])),
    AtcRational(Uint256([21194852233746400, 0, 0, 0])),
    AtcRational(Uint256([20952446492814320, 0, 0, 0])),
    AtcRational(Uint256([20712809252003940, 0, 0, 0])),
    AtcRational(Uint256([20475908981085852, 0, 0, 0])),
    AtcRational(Uint256([20241714506910040, 0, 0, 0])),
    AtcRational(Uint256([20010195009407928, 0, 0, 0])),
    AtcRational(Uint256([19781320017637956, 0, 0, 0])),
    AtcRational(Uint256([19555059405874636, 0, 0, 0])),
    AtcRational(Uint256([19331383389740252, 0, 0, 0])),
    AtcRational(Uint256([19110262522378940, 0, 0, 0])),
    AtcRational(Uint256([18891667690672852, 0, 0, 0])),
    AtcRational(Uint256([18675570111499620, 0, 0, 0])),
    AtcRational(Uint256([18461941328030932, 0, 0, 0])),
    AtcRational(Uint256([18250753206071836, 0, 0, 0])),
    AtcRational(Uint256([18041977930440052, 0, 0, 0])),
    AtcRational(Uint256([17835588001385282, 0, 0, 0])),
];

#[cfg(test)]
mod test {
    use stacks_common::util::hash::to_hex;
    use stacks_common::util::uint::Uint256;

    use crate::chainstate::burn::atc::AtcRational;
    use crate::chainstate::burn::BlockSnapshot;
    use crate::stacks_common::util::uint::BitArray;

    impl AtcRational {
        /// Convert to f64, and panic on conversion failure
        pub fn to_f64(&self) -> f64 {
            let ipart = self.ipart() as f64;
            let fpart = self.0.low_u64() as f64;
            ipart + (fpart / (u64::MAX as f64))
        }

        /// Convert from f64 between 0 and 1, panicking on conversion failure.  Scales up the f64 so that its
        /// fractional parts reside in the lower 64 bits of the AtcRational.
        pub fn from_f64_unit(value: f64) -> Self {
            if value < 0.0 || value >= 1.0 {
                panic!("only usable for values in [0.0, 1.0) range");
            }

            // NOTE: this only changes the exponent, not the mantissa.
            // Moreover, u128::from(u64::MAX) + 1 has f64 representation 0x43f0000000000000, so these conversions are safe.
            let scaled_value = value * ((u128::from(u64::MAX) + 1) as f64);

            // this is safe, because 0.0 <= value < 1.0, so scaled_value <= u64::MAX
            let value_u64 = scaled_value as u64;
            Self(Uint256::from_u64(value_u64))
        }
    }

    fn check_add(num_1: u64, den_1: u64, num_2: u64, den_2: u64) {
        assert!(
            (AtcRational::frac(num_1, den_1)
                .add(&AtcRational::frac(num_2, den_2))
                .unwrap())
            .to_f64()
            .abs()
                - (num_1 as f64 / den_1 as f64 + num_2 as f64 / den_2 as f64).abs()
                < (1.0 / (1024.0 * 1024.0))
        );
    }

    fn check_mul(num_1: u64, den_1: u64, num_2: u64, den_2: u64) {
        assert!(
            (AtcRational::frac(num_1, den_1)
                .mul(&AtcRational::frac(num_2, den_2))
                .unwrap())
            .to_f64()
            .abs()
                - ((num_1 as f64 / den_1 as f64) * (num_2 as f64 / den_2 as f64)).abs()
                < (1.0 / (1024.0 * 1024.0))
        );
    }

    #[test]
    fn test_atc_rational() {
        // zero
        assert_eq!(AtcRational::zero().into_inner(), Uint256::from_u64(0));

        // one
        assert_eq!(AtcRational::one().into_inner(), Uint256::one() << 64);

        // one_sup
        assert_eq!(
            AtcRational::one_sup().into_inner(),
            (Uint256::one() << 64) - Uint256::from_u64(1)
        );

        // max
        assert_eq!(
            AtcRational::max().into_inner(),
            (Uint256::from_u64(u64::MAX) << 64) | Uint256::from_u64(u64::MAX)
        );

        // ipart
        assert_eq!(AtcRational::one().ipart(), 1);
        assert_eq!(AtcRational::frac(1, 2).ipart(), 0);
        assert_eq!(AtcRational::frac(3, 2).ipart(), 1);
        assert_eq!(AtcRational::frac(4, 2).ipart(), 2);
        assert_eq!(AtcRational::frac(9999, 10000).ipart(), 0);

        // to_f64
        assert_eq!(AtcRational::one().to_f64(), 1.0);
        assert_eq!(AtcRational::zero().to_f64(), 0.0);
        assert_eq!(AtcRational::frac(1, 2).to_f64(), 0.5);
        assert_eq!(AtcRational::frac(1, 32).to_f64(), 0.03125);

        // from_f64_unit
        assert_eq!(AtcRational::from_f64_unit(0.0), AtcRational::zero());
        assert_eq!(AtcRational::from_f64_unit(0.5), AtcRational::frac(1, 2));
        assert_eq!(
            AtcRational::from_f64_unit(0.03125),
            AtcRational::frac(1, 32)
        );

        // is_overflowed
        assert!(!AtcRational::max().is_overflowed());
        assert!(
            AtcRational(AtcRational::max().into_inner() + Uint256::from_u64(1)).is_overflowed()
        );
        assert!(AtcRational::max()
            .add(&AtcRational(Uint256::from_u64(1)))
            .is_none());

        // frac constructor produces values between 0 and u64::MAX
        assert_eq!(AtcRational::frac(1, 1), AtcRational::one());
        assert_eq!(
            AtcRational::frac(1, 2).0,
            Uint256::from_u64(u64::MAX / 2) + Uint256::from_u64(1)
        );
        assert_eq!(
            AtcRational::frac(1, 4).0,
            Uint256::from_u64(u64::MAX / 4) + Uint256::from_u64(1)
        );
        assert_eq!(
            AtcRational::frac(1, 8).0,
            Uint256::from_u64(u64::MAX / 8) + Uint256::from_u64(1)
        );
        assert_eq!(
            AtcRational::frac(1, 16).0,
            Uint256::from_u64(u64::MAX / 16) + Uint256::from_u64(1)
        );
        assert_eq!(
            AtcRational::frac(1, 32).0,
            Uint256::from_u64(u64::MAX / 32) + Uint256::from_u64(1)
        );

        // fractions auto-normalize
        assert_eq!(AtcRational::frac(2, 4), AtcRational::frac(1, 2));
        assert_eq!(AtcRational::frac(100, 400), AtcRational::frac(1, 4));
        assert_eq!(AtcRational::frac(5, 25), AtcRational::frac(1, 5));

        // fractions can be added
        assert_eq!(
            AtcRational::frac(1, 2)
                .add(&AtcRational::frac(1, 2))
                .unwrap(),
            AtcRational::one()
        );
        assert_eq!(
            AtcRational::frac(1, 4)
                .add(&AtcRational::frac(1, 4))
                .unwrap(),
            AtcRational::frac(1, 2)
        );
        assert_eq!(
            AtcRational::frac(1, 8)
                .add(&AtcRational::frac(1, 8))
                .unwrap(),
            AtcRational::frac(1, 4)
        );
        assert_eq!(
            AtcRational::frac(3, 8)
                .add(&AtcRational::frac(3, 8))
                .unwrap(),
            AtcRational::frac(3, 4)
        );
        assert_eq!(
            AtcRational::max().add(&AtcRational(Uint256::from_u64(1))),
            None
        );

        // fractions can be subtracted
        assert_eq!(
            AtcRational::frac(1, 2)
                .sub(&AtcRational::frac(1, 2))
                .unwrap(),
            AtcRational::zero()
        );
        assert_eq!(
            AtcRational::one().sub(&AtcRational::frac(1, 2)).unwrap(),
            AtcRational::frac(1, 2)
        );
        assert_eq!(
            AtcRational::one().sub(&AtcRational::frac(1, 32)).unwrap(),
            AtcRational::frac(31, 32)
        );

        // fractions can be multiplied
        assert_eq!(
            AtcRational::frac(1, 2)
                .mul(&AtcRational::frac(1, 2))
                .unwrap(),
            AtcRational::frac(1, 4)
        );
        assert_eq!(
            AtcRational::frac(5, 6)
                .mul(&AtcRational::frac(7, 8))
                .unwrap(),
            AtcRational::frac(35, 48)
        );
        assert_eq!(
            AtcRational::frac(100, 2)
                .mul(&AtcRational::frac(200, 4))
                .unwrap(),
            AtcRational::frac(20000, 8)
        );
        assert_eq!(
            AtcRational::frac(1, 2)
                .mul(&AtcRational::frac(1024, 1))
                .unwrap(),
            AtcRational::frac(512, 1)
        );

        assert_eq!(
            AtcRational::frac(1, 2).min(&AtcRational::frac(15, 32)),
            AtcRational::frac(15, 32)
        );

        // we only do stuff with an AtcRational in the range [0..1), since if the ATC-C is greater
        // than 1.0, then the null miner never wins (and thus there's no need to compute the null
        // miner probability).
        //
        // The only time an AtcRational is greater than 1.0 is when we scale it up to the lookup
        // table index, which has 1024 items.  We check that here as well.
        for num_1 in 0..=1 {
            for den_1 in 1..=1024 {
                test_debug!("{}/{}", num_1, den_1);
                for num_2 in 0..=1 {
                    for den_2 in 1..=1024 {
                        check_add(num_1, den_1, num_2, den_2);
                        check_mul(num_1, den_1, num_2, den_2);
                        check_mul(num_1, den_1, 1024, 1);
                        check_mul(num_2, den_2, 1024, 1);
                    }
                }
            }
        }
    }

    #[test]
    #[ignore]
    fn print_functions() {
        let mut grid: Vec<Vec<char>> = vec![vec![' '; 100]; 102];
        for i in 0..100 {
            let f_atc = (i as f64) / 100.0;
            let atc = AtcRational::frac(i as u64, 100);
            let l_atc = BlockSnapshot::null_miner_logistic(atc).to_f64();
            let p_atc = BlockSnapshot::null_miner_probability(atc).to_f64();

            // NOTE: columns increase downwards, so flip this
            let l_atc_100 = 100 - ((l_atc * 100.0) as usize);
            let p_atc_100 = 100 - ((p_atc * 100.0) as usize);
            let a_atc_100 = 100 - (((1.0 - f_atc) * 100.0) as usize);
            grid[a_atc_100][i] = '$';
            grid[l_atc_100][i] = '#';
            grid[p_atc_100][i] = '^';
        }
        for j in 0..100 {
            grid[101][j] = '_';
        }

        println!("");
        for row in grid.iter() {
            let grid_str: String = row.clone().into_iter().collect();
            println!("|{}", &grid_str);
        }
    }

    /// Calculate the logic advantage curve for the null miner.
    /// This function's parameters are chosen such that:
    /// * if the ATC carryover has diminished by less than 20%, the null miner has negligible
    /// chances of winning.  This is to avoid punishing honest miners when there are flash blocks.
    /// * If the ATC carryover has diminished by between 20% and 80%, the null miner has a
    /// better-than-linear probability of winning.  That is, if the burnchain MEV miner pays less
    /// than X% of the expected carryover (20% <= X < 80%), then their probability of winning is
    /// (1) strictly less than X%, and (2) strictly less than any Pr[X% - c] for 0 < c < X.
    /// * If the ATC carryover is less than 20%, the null miner has an overwhelmingly likely chance
    /// of winning (>95%).
    ///
    /// The logistic curve fits the points (atc=0.2, null_prob=0.75) and (atc=0.8, null_prob=0.01).
    fn null_miner_logistic(atc: f64) -> f64 {
        // recall the inverted logistic function:
        //
        //                 L
        // f(x) = ---------------------
        //                -k * (x0 - x)
        //           1 + e
        //
        // It is shaped like a *backwards* "S" -- it approaches L as `x` tends towards negative
        // infinity, and it approaches 0 as `x` tends towards positive infinity.  This function is
        // the null miner advantage function, where `x` is the ATC carryover value.
        //
        // We need to drive x0 and k from our two points:
        //
        // (x1, y1) = (0.2, 0.75)
        // (x2, y2) = (0.8, 0.01)
        //
        // to derive L, x0, and k:
        // L = 0.8
        // z = ln(L/y1 - 1) / ln(L/y2 - 1)
        // x0 = (x1 - z * x2) / (1 - z)
        // k = ln(L/y1 - 1) / (x1 - x0)
        //
        // The values for x0 and k were generated with the following GNU bc script:
        // ```
        // $ cat /tmp/variables.bc
        // scale=32
        // supremum=0.8   /* this is L */
        // x1=0.2
        // y1=0.75
        // x2=0.8
        // y2=0.01
        // z=l(supremum/y1 - 1)/l(supremum/y2 -1)
        // x0=(x1 - z * x2)/(1 - z)
        // k=l(supremum/y1 - 1)/(x1 - x0)
        // print "x0 = "; x0
        // print "k = "; k
        // ```
        //
        // This script evaluates to:
        // ```
        // $ bc -l < /tmp/variables.bc
        // x0 = .42957690816204645842320195118064
        // k = 11.79583008928205260028158351938437
        // ```

        let L: f64 = 0.8;

        // truncated f64
        let x0: f64 = 0.42957690816204647;
        let k: f64 = 11.795830089282052;

        // natural logarithm constant
        let e: f64 = 2.718281828459045;

        let adv = L / (1.0 + e.powf(-k * (x0 - atc)));
        adv
    }

    #[test]
    fn make_null_miner_lookup_table() {
        use crate::chainstate::burn::atc::ATC_LOOKUP;
        let mut lookup_table = Vec::with_capacity(1024);
        for atc in 0..1024 {
            let fatc = (atc as f64) / 1024.0;
            let lgst_fatc = null_miner_logistic(fatc);
            let lgst_rational = AtcRational::from_f64_unit(lgst_fatc);
            assert_eq!(ATC_LOOKUP[atc], lgst_rational);
            assert_eq!(ATC_LOOKUP[atc].to_f64(), lgst_fatc);
            lookup_table.push(lgst_rational);
        }
        println!("[");
        for lt in lookup_table.into_iter() {
            let inner = lt.into_inner();
            println!("   AtcRational(Uint256({:?})),", &inner.0);
        }
        println!("]");
    }
}
