fn main() {
    println!("Hello, world!");
}

#[cfg(test)]
mod tests {
    use stacks_lib::chainstate::stacks::index::node::*;

    use crate::tests::utils::count_back_ptrs;

    mod utils {
        use std::collections::HashMap;

        use regex::Regex;
        use stacks_lib::chainstate::stacks::index::node::*;
        use stacks_lib::types::chainstate::StacksBlockId;
        use stacks_lib::util::hash::hex_bytes;

        pub fn parse_trie_ptr(s: &str) -> Option<TriePtr> {
            let re =
                Regex::new(r"id\((\d+)\)chr\(([0-9a-fA-F]{2})\)ptr\((\d+)\)bblk\((\d+)\)").ok()?;

            let caps = re.captures(s)?;

            Some(TriePtr {
                id: caps[1].parse().ok()?,
                chr: u8::from_str_radix(&caps[2], 16).ok()?,
                ptr: caps[3].parse().ok()?,
                back_block: caps[4].parse().ok()?,
            })
        }

        pub fn parse_trie_node_256(s: &str) -> TrieNodeType {
            let s = s
                .strip_prefix("TrieNode256(")
                .unwrap()
                .strip_suffix(")")
                .unwrap();

            let mut path = Vec::new();
            let mut ptrs = [TriePtr {
                id: 0,
                chr: 0,
                ptr: 0,
                back_block: 0,
            }; 256];

            // Split path and ptrs
            //println!("=== Split");
            let parts: Vec<&str> = s.split(" ptrs=").collect();
            if parts.len() != 2 {
                panic!("len should be 2");
            }

            // Parse path (hex string, empty allowed)
            //println!("=== Parse path");
            if let Some(path_str) = parts[0].strip_prefix("path=") {
                if !path_str.is_empty() {
                    path = hex_bytes(s).unwrap();
                }
            }

            // Parse ptr list
            //println!("=== Parse list");
            for (i, ptr_str) in parts[1].split(',').enumerate() {
                if i >= 256 {
                    break;
                }
                //println!("[{i}] {ptr_str}");
                ptrs[i] = parse_trie_ptr(ptr_str).unwrap();
            }

            TrieNodeType::Node256(Box::new(TrieNode256 {
                path,
                ptrs,
                cowptr: None,
                patches: Vec::new(),
            }))
        }

        pub fn count_full_ptrs(node: &TrieNodeType) -> usize {
            let mut count = 0;
            if !node.is_leaf() {
                for ptr in node.ptrs().iter() {
                    if !ptr.is_empty() && !is_backptr(ptr.id) {
                        count += 1;
                    }
                }
            }
            count
        }

        pub fn count_back_ptrs(node: &TrieNodeType) -> usize {
            node.ptrs()
                .iter()
                .filter(|ptr| is_backptr(ptr.id()))
                .count()
        }

        pub fn parse_cow_ptr(s: &str) -> TrieCowPtr {
            let inner = s
                .strip_prefix("TrieCowPtr(")
                .unwrap()
                .strip_suffix(")")
                .unwrap();

            // split once at the first comma
            let mut parts = inner.splitn(2, ',');

            let hash_str = parts.next().unwrap().trim();
            let ptr_str = parts.next().unwrap().trim();

            let bytes = hex_bytes(hash_str).unwrap();
            if bytes.len() != 32 {
                panic!("len should be 32");
            }

            let mut hash = [0u8; 32];
            hash.copy_from_slice(&bytes);

            let ptr = parse_trie_ptr(ptr_str).unwrap();

            let block_id = StacksBlockId::from_bytes(&hash).unwrap();

            TrieCowPtr::new(block_id, ptr)
        }

        #[allow(dead_code)]
        pub fn id_count(node: &TrieNodeType) -> HashMap<u8, usize> {
            let mut counts: HashMap<u8, usize> = HashMap::new();

            for ptr in node.ptrs().iter() {
                *counts.entry(ptr.id()).or_insert(0) += 1;
            }

            return counts;
        }
    }

    #[test]
    fn test_bug_fix_genesis_testnet_try_from_nodetype() {
        let base_ptr = "TrieCowPtr(a9d914ea8d70cbb097a3101f8d52a6d11a5100fa1ac41f3606be76bad00487be,id(134)chr(00)ptr(36)bblk(9507))";

        // Node 256 full with all character from 0 (00) to 255 (ff)
        // 248 are Backptr (133 to Node5) and 8 are not Backptr
        let old_node = "TrieNode256(path= ptrs=id(133)chr(00)ptr(452)bblk(9449),id(133)chr(01)ptr(3034)bblk(9449),id(133)chr(02)ptr(416)bblk(9498),id(133)chr(03)ptr(496)bblk(9437),id(133)chr(04)ptr(128)bblk(9460),id(133)chr(05)ptr(128)bblk(9467),id(133)chr(06)ptr(128)bblk(9429),id(133)chr(07)ptr(3084)bblk(9449),id(133)chr(08)ptr(128)bblk(9461),id(133)chr(09)ptr(422)bblk(9417),id(133)chr(0a)ptr(466)bblk(9498),id(133)chr(0b)ptr(2598)bblk(9425),id(133)chr(0c)ptr(128)bblk(9493),id(133)chr(0d)ptr(3048)bblk(9395),id(133)chr(0e)ptr(134)bblk(9469),id(133)chr(0f)ptr(3184)bblk(9449),id(133)chr(10)ptr(128)bblk(9225),id(133)chr(11)ptr(184)bblk(9469),id(133)chr(12)ptr(128)bblk(9506),id(133)chr(13)ptr(2944)bblk(9338),id(133)chr(14)ptr(516)bblk(9498),id(133)chr(15)ptr(128)bblk(9438),id(133)chr(16)ptr(178)bblk(9431),id(133)chr(17)ptr(178)bblk(9503),id(133)chr(18)ptr(140)bblk(9499),id(133)chr(19)ptr(672)bblk(9498),id(133)chr(1a)ptr(3284)bblk(9449),id(5)chr(1b)ptr(128)bblk(0),id(133)chr(1c)ptr(672)bblk(9407),id(133)chr(1d)ptr(722)bblk(9498),id(133)chr(1e)ptr(740)bblk(9335),id(133)chr(1f)ptr(128)bblk(9420),id(133)chr(20)ptr(678)bblk(9417),id(133)chr(21)ptr(772)bblk(9498),id(133)chr(22)ptr(3334)bblk(9449),id(133)chr(23)ptr(5910)bblk(9437),id(133)chr(24)ptr(128)bblk(9501),id(133)chr(25)ptr(5960)bblk(9437),id(133)chr(26)ptr(628)bblk(9401),id(133)chr(27)ptr(3384)bblk(9449),id(133)chr(28)ptr(3400)bblk(9407),id(133)chr(29)ptr(6010)bblk(9437),id(133)chr(2a)ptr(822)bblk(9498),id(5)chr(2b)ptr(178)bblk(0),id(133)chr(2c)ptr(872)bblk(9498),id(133)chr(2d)ptr(2648)bblk(9505),id(133)chr(2e)ptr(922)bblk(9498),id(133)chr(2f)ptr(6110)bblk(9437),id(133)chr(30)ptr(278)bblk(9453),id(5)chr(31)ptr(228)bblk(0),id(133)chr(32)ptr(928)bblk(9417),id(133)chr(33)ptr(972)bblk(9498),id(133)chr(34)ptr(178)bblk(9472),id(133)chr(35)ptr(1022)bblk(9498),id(133)chr(36)ptr(1072)bblk(9498),id(133)chr(37)ptr(1090)bblk(9335),id(133)chr(38)ptr(3484)bblk(9449),id(133)chr(39)ptr(178)bblk(9458),id(133)chr(3a)ptr(1190)bblk(9335),id(133)chr(3b)ptr(2826)bblk(9415),id(133)chr(3c)ptr(178)bblk(9455),id(133)chr(3d)ptr(2710)bblk(9476),id(133)chr(3e)ptr(2814)bblk(9497),id(133)chr(3f)ptr(3584)bblk(9449),id(133)chr(40)ptr(2648)bblk(9489),id(133)chr(41)ptr(1122)bblk(9498),id(133)chr(42)ptr(220)bblk(9354),id(133)chr(43)ptr(8996)bblk(9437),id(133)chr(44)ptr(228)bblk(9455),id(133)chr(45)ptr(1296)bblk(9335),id(133)chr(46)ptr(1172)bblk(9498),id(133)chr(47)ptr(1222)bblk(9498),id(133)chr(48)ptr(1272)bblk(9498),id(133)chr(49)ptr(178)bblk(9470),id(133)chr(4a)ptr(3862)bblk(9498),id(133)chr(4b)ptr(3740)bblk(9449),id(133)chr(4c)ptr(9252)bblk(9437),id(133)chr(4d)ptr(6336)bblk(9407),id(133)chr(4e)ptr(178)bblk(9468),id(133)chr(4f)ptr(3790)bblk(9449),id(133)chr(50)ptr(6386)bblk(9407),id(133)chr(51)ptr(3912)bblk(9498),id(133)chr(52)ptr(9302)bblk(9437),id(133)chr(53)ptr(290)bblk(9499),id(133)chr(54)ptr(134)bblk(9426),id(133)chr(55)ptr(3962)bblk(9498),id(133)chr(56)ptr(9018)bblk(9407),id(133)chr(57)ptr(178)bblk(9483),id(133)chr(58)ptr(11938)bblk(9437),id(133)chr(59)ptr(328)bblk(9174),id(133)chr(5a)ptr(3890)bblk(9449),id(5)chr(5b)ptr(278)bblk(0),id(133)chr(5c)ptr(3990)bblk(9449),id(133)chr(5d)ptr(4040)bblk(9449),id(133)chr(5e)ptr(228)bblk(9458),id(133)chr(5f)ptr(4012)bblk(9498),id(133)chr(60)ptr(4062)bblk(9498),id(5)chr(61)ptr(2864)bblk(0),id(133)chr(62)ptr(272)bblk(9486),id(133)chr(63)ptr(9174)bblk(9407),id(133)chr(64)ptr(4140)bblk(9449),id(133)chr(65)ptr(4162)bblk(9498),id(133)chr(66)ptr(4212)bblk(9498),id(133)chr(67)ptr(9274)bblk(9407),id(133)chr(68)ptr(4262)bblk(9498),id(133)chr(69)ptr(4312)bblk(9498),id(133)chr(6a)ptr(278)bblk(9463),id(133)chr(6b)ptr(278)bblk(9462),id(133)chr(6c)ptr(234)bblk(9242),id(133)chr(6d)ptr(4290)bblk(9449),id(133)chr(6e)ptr(328)bblk(9462),id(133)chr(6f)ptr(7816)bblk(9505),id(133)chr(70)ptr(12152)bblk(9335),id(133)chr(71)ptr(328)bblk(9327),id(133)chr(72)ptr(2864)bblk(9504),id(133)chr(73)ptr(4340)bblk(9449),id(133)chr(74)ptr(4362)bblk(9498),id(133)chr(75)ptr(278)bblk(9478),id(133)chr(76)ptr(234)bblk(9296),id(133)chr(77)ptr(4412)bblk(9498),id(133)chr(78)ptr(4462)bblk(9498),id(133)chr(79)ptr(4512)bblk(9498),id(133)chr(7a)ptr(5280)bblk(9473),id(5)chr(7b)ptr(2914)bblk(0),id(133)chr(7c)ptr(278)bblk(9490),id(133)chr(7d)ptr(14778)bblk(9437),id(133)chr(7e)ptr(2810)bblk(9476),id(133)chr(7f)ptr(4562)bblk(9498),id(133)chr(80)ptr(228)bblk(9495),id(133)chr(81)ptr(234)bblk(9477),id(133)chr(82)ptr(2864)bblk(9295),id(133)chr(83)ptr(4618)bblk(9498),id(133)chr(84)ptr(6720)bblk(9417),id(133)chr(85)ptr(9430)bblk(9407),id(133)chr(86)ptr(284)bblk(9500),id(133)chr(87)ptr(14928)bblk(9437),id(133)chr(88)ptr(278)bblk(9494),id(133)chr(89)ptr(2864)bblk(9399),id(133)chr(8a)ptr(4668)bblk(9498),id(133)chr(8b)ptr(5454)bblk(9504),id(133)chr(8c)ptr(2864)bblk(9450),id(133)chr(8d)ptr(4768)bblk(9498),id(133)chr(8e)ptr(278)bblk(9506),id(133)chr(8f)ptr(6906)bblk(9401),id(133)chr(90)ptr(278)bblk(9432),id(133)chr(91)ptr(284)bblk(9456),id(133)chr(92)ptr(328)bblk(9451),id(133)chr(93)ptr(378)bblk(9454),id(133)chr(94)ptr(7006)bblk(9401),id(133)chr(95)ptr(234)bblk(9491),id(133)chr(96)ptr(4874)bblk(9498),id(133)chr(97)ptr(4936)bblk(9498),id(133)chr(98)ptr(17714)bblk(9437),id(133)chr(99)ptr(378)bblk(9343),id(133)chr(9a)ptr(4790)bblk(9449),id(133)chr(9b)ptr(278)bblk(9427),id(133)chr(9c)ptr(7110)bblk(9395),id(133)chr(9d)ptr(4840)bblk(9449),id(133)chr(9e)ptr(4890)bblk(9449),id(133)chr(9f)ptr(4992)bblk(9498),id(133)chr(a0)ptr(2914)bblk(9471),id(133)chr(a1)ptr(620)bblk(9354),id(133)chr(a2)ptr(17864)bblk(9437),id(133)chr(a3)ptr(7570)bblk(9498),id(133)chr(a4)ptr(328)bblk(9445),id(133)chr(a5)ptr(434)bblk(9428),id(133)chr(a6)ptr(7156)bblk(9401),id(133)chr(a7)ptr(7620)bblk(9498),id(133)chr(a8)ptr(5380)bblk(9473),id(133)chr(a9)ptr(7220)bblk(9417),id(133)chr(aa)ptr(17914)bblk(9437),id(133)chr(ab)ptr(378)bblk(9482),id(133)chr(ac)ptr(7670)bblk(9498),id(133)chr(ad)ptr(378)bblk(9475),id(133)chr(ae)ptr(7270)bblk(9417),id(133)chr(af)ptr(6178)bblk(9390),id(133)chr(b0)ptr(384)bblk(9442),id(133)chr(b1)ptr(7320)bblk(9417),id(133)chr(b2)ptr(14952)bblk(9407),id(133)chr(b3)ptr(2864)bblk(9443),id(133)chr(b4)ptr(7720)bblk(9498),id(133)chr(b5)ptr(334)bblk(9502),id(133)chr(b6)ptr(328)bblk(9481),id(133)chr(b7)ptr(278)bblk(9488),id(133)chr(b8)ptr(384)bblk(9502),id(133)chr(b9)ptr(7770)bblk(9498),id(133)chr(ba)ptr(7820)bblk(9498),id(133)chr(bb)ptr(5196)bblk(9449),id(133)chr(bc)ptr(7870)bblk(9498),id(133)chr(bd)ptr(18064)bblk(9437),id(133)chr(be)ptr(328)bblk(9430),id(133)chr(bf)ptr(328)bblk(9412),id(133)chr(c0)ptr(378)bblk(9161),id(133)chr(c1)ptr(7556)bblk(9401),id(133)chr(c2)ptr(5246)bblk(9449),id(133)chr(c3)ptr(334)bblk(9465),id(133)chr(c4)ptr(378)bblk(9427),id(133)chr(c5)ptr(2920)bblk(9477),id(133)chr(c6)ptr(378)bblk(9420),id(133)chr(c7)ptr(4156)bblk(9338),id(133)chr(c8)ptr(18114)bblk(9437),id(133)chr(c9)ptr(18164)bblk(9437),id(133)chr(ca)ptr(2864)bblk(9506),id(133)chr(cb)ptr(5346)bblk(9449),id(133)chr(cc)ptr(5396)bblk(9449),id(133)chr(cd)ptr(7770)bblk(9417),id(133)chr(ce)ptr(7756)bblk(9401),id(133)chr(cf)ptr(7926)bblk(9498),id(133)chr(d0)ptr(328)bblk(9483),id(133)chr(d1)ptr(5446)bblk(9449),id(133)chr(d2)ptr(440)bblk(9499),id(5)chr(d3)ptr(2964)bblk(0),id(133)chr(d4)ptr(8026)bblk(9498),id(133)chr(d5)ptr(18486)bblk(9335),id(133)chr(d6)ptr(18320)bblk(9437),id(133)chr(d7)ptr(10108)bblk(9395),id(133)chr(d8)ptr(434)bblk(9479),id(133)chr(d9)ptr(5552)bblk(9449),id(133)chr(da)ptr(384)bblk(9432),id(133)chr(db)ptr(2974)bblk(9322),id(133)chr(dc)ptr(2920)bblk(9496),id(133)chr(dd)ptr(2970)bblk(9506),id(133)chr(de)ptr(434)bblk(9255),id(133)chr(df)ptr(8076)bblk(9498),id(133)chr(e0)ptr(434)bblk(9493),id(133)chr(e1)ptr(8242)bblk(9449),id(133)chr(e2)ptr(8292)bblk(9449),id(133)chr(e3)ptr(2916)bblk(9491),id(133)chr(e4)ptr(384)bblk(9466),id(133)chr(e5)ptr(484)bblk(9502),id(133)chr(e6)ptr(8126)bblk(9498),id(133)chr(e7)ptr(8176)bblk(9498),id(133)chr(e8)ptr(434)bblk(9495),id(133)chr(e9)ptr(434)bblk(9492),id(133)chr(ea)ptr(484)bblk(9414),id(133)chr(eb)ptr(434)bblk(9488),id(133)chr(ec)ptr(18470)bblk(9437),id(133)chr(ed)ptr(434)bblk(9467),id(133)chr(ee)ptr(484)bblk(9469),id(133)chr(ef)ptr(434)bblk(9459),id(133)chr(f0)ptr(2962)bblk(9434),id(133)chr(f1)ptr(434)bblk(9357),id(133)chr(f2)ptr(8226)bblk(9498),id(133)chr(f3)ptr(18152)bblk(9407),id(5)chr(f4)ptr(3020)bblk(0),id(133)chr(f5)ptr(484)bblk(9336),id(133)chr(f6)ptr(8182)bblk(9417),id(133)chr(f7)ptr(18302)bblk(9407),id(133)chr(f8)ptr(3024)bblk(9503),id(133)chr(f9)ptr(8288)bblk(9417),id(133)chr(fa)ptr(11078)bblk(9449),id(133)chr(fb)ptr(10658)bblk(9395),id(133)chr(fc)ptr(484)bblk(9433),id(133)chr(fd)ptr(534)bblk(9500),id(133)chr(fe)ptr(11128)bblk(9449),id(133)chr(ff)ptr(8338)bblk(9417))";

        // Node 256 full with all character from 0 (00) to 255 (ff)
        // 201 are Backptr (133 to Node5) and 55 are not Backptr
        let new_node = "TrieNode256(path= ptrs=id(133)chr(00)ptr(452)bblk(9449),id(133)chr(01)ptr(3034)bblk(9449),id(133)chr(02)ptr(416)bblk(9498),id(133)chr(03)ptr(496)bblk(9437),id(5)chr(04)ptr(78)bblk(0),id(133)chr(05)ptr(128)bblk(9467),id(133)chr(06)ptr(128)bblk(9429),id(133)chr(07)ptr(3084)bblk(9449),id(5)chr(08)ptr(172)bblk(0),id(5)chr(09)ptr(169)bblk(0),id(133)chr(0a)ptr(466)bblk(9498),id(5)chr(0b)ptr(84)bblk(0),id(133)chr(0c)ptr(128)bblk(9493),id(5)chr(0d)ptr(106)bblk(0),id(133)chr(0e)ptr(134)bblk(9469),id(133)chr(0f)ptr(3184)bblk(9449),id(5)chr(10)ptr(24)bblk(0),id(133)chr(11)ptr(184)bblk(9469),id(133)chr(12)ptr(128)bblk(9506),id(133)chr(13)ptr(2944)bblk(9338),id(133)chr(14)ptr(516)bblk(9498),id(133)chr(15)ptr(128)bblk(9438),id(133)chr(16)ptr(178)bblk(9431),id(133)chr(17)ptr(178)bblk(9503),id(5)chr(18)ptr(163)bblk(0),id(133)chr(19)ptr(672)bblk(9498),id(133)chr(1a)ptr(3284)bblk(9449),id(5)chr(1b)ptr(128)bblk(0),id(133)chr(1c)ptr(672)bblk(9407),id(5)chr(1d)ptr(142)bblk(0),id(133)chr(1e)ptr(740)bblk(9335),id(133)chr(1f)ptr(128)bblk(9420),id(133)chr(20)ptr(678)bblk(9417),id(133)chr(21)ptr(772)bblk(9498),id(133)chr(22)ptr(3334)bblk(9449),id(133)chr(23)ptr(5910)bblk(9437),id(133)chr(24)ptr(128)bblk(9501),id(5)chr(25)ptr(125)bblk(0),id(133)chr(26)ptr(628)bblk(9401),id(133)chr(27)ptr(3384)bblk(9449),id(133)chr(28)ptr(3400)bblk(9407),id(133)chr(29)ptr(6010)bblk(9437),id(133)chr(2a)ptr(822)bblk(9498),id(133)chr(2b)ptr(178)bblk(9507),id(133)chr(2c)ptr(872)bblk(9498),id(133)chr(2d)ptr(2648)bblk(9505),id(133)chr(2e)ptr(922)bblk(9498),id(133)chr(2f)ptr(6110)bblk(9437),id(133)chr(30)ptr(278)bblk(9453),id(133)chr(31)ptr(228)bblk(9507),id(133)chr(32)ptr(928)bblk(9417),id(133)chr(33)ptr(972)bblk(9498),id(133)chr(34)ptr(178)bblk(9472),id(133)chr(35)ptr(1022)bblk(9498),id(133)chr(36)ptr(1072)bblk(9498),id(133)chr(37)ptr(1090)bblk(9335),id(133)chr(38)ptr(3484)bblk(9449),id(5)chr(39)ptr(21)bblk(0),id(133)chr(3a)ptr(1190)bblk(9335),id(133)chr(3b)ptr(2826)bblk(9415),id(5)chr(3c)ptr(66)bblk(0),id(133)chr(3d)ptr(2710)bblk(9476),id(133)chr(3e)ptr(2814)bblk(9497),id(5)chr(3f)ptr(57)bblk(0),id(133)chr(40)ptr(2648)bblk(9489),id(5)chr(41)ptr(114)bblk(0),id(133)chr(42)ptr(220)bblk(9354),id(133)chr(43)ptr(8996)bblk(9437),id(133)chr(44)ptr(228)bblk(9455),id(133)chr(45)ptr(1296)bblk(9335),id(133)chr(46)ptr(1172)bblk(9498),id(133)chr(47)ptr(1222)bblk(9498),id(133)chr(48)ptr(1272)bblk(9498),id(5)chr(49)ptr(15)bblk(0),id(5)chr(4a)ptr(32)bblk(0),id(133)chr(4b)ptr(3740)bblk(9449),id(133)chr(4c)ptr(9252)bblk(9437),id(133)chr(4d)ptr(6336)bblk(9407),id(133)chr(4e)ptr(178)bblk(9468),id(133)chr(4f)ptr(3790)bblk(9449),id(5)chr(50)ptr(93)bblk(0),id(133)chr(51)ptr(3912)bblk(9498),id(133)chr(52)ptr(9302)bblk(9437),id(133)chr(53)ptr(290)bblk(9499),id(133)chr(54)ptr(134)bblk(9426),id(133)chr(55)ptr(3962)bblk(9498),id(133)chr(56)ptr(9018)bblk(9407),id(133)chr(57)ptr(178)bblk(9483),id(5)chr(58)ptr(184)bblk(0),id(133)chr(59)ptr(328)bblk(9174),id(133)chr(5a)ptr(3890)bblk(9449),id(5)chr(5b)ptr(11)bblk(0),id(133)chr(5c)ptr(3990)bblk(9449),id(5)chr(5d)ptr(60)bblk(0),id(133)chr(5e)ptr(228)bblk(9458),id(133)chr(5f)ptr(4012)bblk(9498),id(133)chr(60)ptr(4062)bblk(9498),id(5)chr(61)ptr(187)bblk(0),id(5)chr(62)ptr(54)bblk(0),id(133)chr(63)ptr(9174)bblk(9407),id(5)chr(64)ptr(27)bblk(0),id(5)chr(65)ptr(18)bblk(0),id(5)chr(66)ptr(119)bblk(0),id(133)chr(67)ptr(9274)bblk(9407),id(133)chr(68)ptr(4262)bblk(9498),id(133)chr(69)ptr(4312)bblk(9498),id(5)chr(6a)ptr(160)bblk(0),id(133)chr(6b)ptr(278)bblk(9462),id(133)chr(6c)ptr(234)bblk(9242),id(5)chr(6d)ptr(139)bblk(0),id(5)chr(6e)ptr(4)bblk(0),id(133)chr(6f)ptr(7816)bblk(9505),id(133)chr(70)ptr(12152)bblk(9335),id(133)chr(71)ptr(328)bblk(9327),id(5)chr(72)ptr(178)bblk(0),id(133)chr(73)ptr(4340)bblk(9449),id(133)chr(74)ptr(4362)bblk(9498),id(133)chr(75)ptr(278)bblk(9478),id(133)chr(76)ptr(234)bblk(9296),id(133)chr(77)ptr(4412)bblk(9498),id(5)chr(78)ptr(63)bblk(0),id(133)chr(79)ptr(4512)bblk(9498),id(133)chr(7a)ptr(5280)bblk(9473),id(133)chr(7b)ptr(2914)bblk(9507),id(133)chr(7c)ptr(278)bblk(9490),id(133)chr(7d)ptr(14778)bblk(9437),id(133)chr(7e)ptr(2810)bblk(9476),id(133)chr(7f)ptr(4562)bblk(9498),id(133)chr(80)ptr(228)bblk(9495),id(5)chr(81)ptr(75)bblk(0),id(133)chr(82)ptr(2864)bblk(9295),id(133)chr(83)ptr(4618)bblk(9498),id(133)chr(84)ptr(6720)bblk(9417),id(5)chr(85)ptr(145)bblk(0),id(133)chr(86)ptr(284)bblk(9500),id(133)chr(87)ptr(14928)bblk(9437),id(133)chr(88)ptr(278)bblk(9494),id(133)chr(89)ptr(2864)bblk(9399),id(133)chr(8a)ptr(4668)bblk(9498),id(133)chr(8b)ptr(5454)bblk(9504),id(133)chr(8c)ptr(2864)bblk(9450),id(133)chr(8d)ptr(4768)bblk(9498),id(133)chr(8e)ptr(278)bblk(9506),id(133)chr(8f)ptr(6906)bblk(9401),id(133)chr(90)ptr(278)bblk(9432),id(133)chr(91)ptr(284)bblk(9456),id(5)chr(92)ptr(175)bblk(0),id(5)chr(93)ptr(122)bblk(0),id(133)chr(94)ptr(7006)bblk(9401),id(5)chr(95)ptr(87)bblk(0),id(5)chr(96)ptr(42)bblk(0),id(133)chr(97)ptr(4936)bblk(9498),id(133)chr(98)ptr(17714)bblk(9437),id(133)chr(99)ptr(378)bblk(9343),id(133)chr(9a)ptr(4790)bblk(9449),id(133)chr(9b)ptr(278)bblk(9427),id(133)chr(9c)ptr(7110)bblk(9395),id(133)chr(9d)ptr(4840)bblk(9449),id(133)chr(9e)ptr(4890)bblk(9449),id(133)chr(9f)ptr(4992)bblk(9498),id(133)chr(a0)ptr(2914)bblk(9471),id(5)chr(a1)ptr(72)bblk(0),id(133)chr(a2)ptr(17864)bblk(9437),id(133)chr(a3)ptr(7570)bblk(9498),id(5)chr(a4)ptr(81)bblk(0),id(5)chr(a5)ptr(38)bblk(0),id(133)chr(a6)ptr(7156)bblk(9401),id(133)chr(a7)ptr(7620)bblk(9498),id(133)chr(a8)ptr(5380)bblk(9473),id(133)chr(a9)ptr(7220)bblk(9417),id(133)chr(aa)ptr(17914)bblk(9437),id(133)chr(ab)ptr(378)bblk(9482),id(5)chr(ac)ptr(181)bblk(0),id(133)chr(ad)ptr(378)bblk(9475),id(133)chr(ae)ptr(7270)bblk(9417),id(5)chr(af)ptr(35)bblk(0),id(133)chr(b0)ptr(384)bblk(9442),id(133)chr(b1)ptr(7320)bblk(9417),id(133)chr(b2)ptr(14952)bblk(9407),id(133)chr(b3)ptr(2864)bblk(9443),id(133)chr(b4)ptr(7720)bblk(9498),id(133)chr(b5)ptr(334)bblk(9502),id(133)chr(b6)ptr(328)bblk(9481),id(133)chr(b7)ptr(278)bblk(9488),id(133)chr(b8)ptr(384)bblk(9502),id(133)chr(b9)ptr(7770)bblk(9498),id(133)chr(ba)ptr(7820)bblk(9498),id(5)chr(bb)ptr(151)bblk(0),id(133)chr(bc)ptr(7870)bblk(9498),id(133)chr(bd)ptr(18064)bblk(9437),id(133)chr(be)ptr(328)bblk(9430),id(5)chr(bf)ptr(48)bblk(0),id(5)chr(c0)ptr(90)bblk(0),id(133)chr(c1)ptr(7556)bblk(9401),id(133)chr(c2)ptr(5246)bblk(9449),id(5)chr(c3)ptr(157)bblk(0),id(133)chr(c4)ptr(378)bblk(9427),id(133)chr(c5)ptr(2920)bblk(9477),id(5)chr(c6)ptr(45)bblk(0),id(133)chr(c7)ptr(4156)bblk(9338),id(133)chr(c8)ptr(18114)bblk(9437),id(133)chr(c9)ptr(18164)bblk(9437),id(133)chr(ca)ptr(2864)bblk(9506),id(5)chr(cb)ptr(131)bblk(0),id(133)chr(cc)ptr(5396)bblk(9449),id(133)chr(cd)ptr(7770)bblk(9417),id(133)chr(ce)ptr(7756)bblk(9401),id(5)chr(cf)ptr(136)bblk(0),id(133)chr(d0)ptr(328)bblk(9483),id(5)chr(d1)ptr(111)bblk(0),id(133)chr(d2)ptr(440)bblk(9499),id(5)chr(d3)ptr(1)bblk(0),id(133)chr(d4)ptr(8026)bblk(9498),id(133)chr(d5)ptr(18486)bblk(9335),id(133)chr(d6)ptr(18320)bblk(9437),id(133)chr(d7)ptr(10108)bblk(9395),id(133)chr(d8)ptr(434)bblk(9479),id(133)chr(d9)ptr(5552)bblk(9449),id(133)chr(da)ptr(384)bblk(9432),id(133)chr(db)ptr(2974)bblk(9322),id(133)chr(dc)ptr(2920)bblk(9496),id(5)chr(dd)ptr(148)bblk(0),id(133)chr(de)ptr(434)bblk(9255),id(133)chr(df)ptr(8076)bblk(9498),id(133)chr(e0)ptr(434)bblk(9493),id(133)chr(e1)ptr(8242)bblk(9449),id(133)chr(e2)ptr(8292)bblk(9449),id(133)chr(e3)ptr(2916)bblk(9491),id(133)chr(e4)ptr(384)bblk(9466),id(133)chr(e5)ptr(484)bblk(9502),id(133)chr(e6)ptr(8126)bblk(9498),id(133)chr(e7)ptr(8176)bblk(9498),id(133)chr(e8)ptr(434)bblk(9495),id(133)chr(e9)ptr(434)bblk(9492),id(133)chr(ea)ptr(484)bblk(9414),id(5)chr(eb)ptr(100)bblk(0),id(5)chr(ec)ptr(51)bblk(0),id(133)chr(ed)ptr(434)bblk(9467),id(133)chr(ee)ptr(484)bblk(9469),id(133)chr(ef)ptr(434)bblk(9459),id(133)chr(f0)ptr(2962)bblk(9434),id(133)chr(f1)ptr(434)bblk(9357),id(133)chr(f2)ptr(8226)bblk(9498),id(133)chr(f3)ptr(18152)bblk(9407),id(5)chr(f4)ptr(8)bblk(0),id(133)chr(f5)ptr(484)bblk(9336),id(133)chr(f6)ptr(8182)bblk(9417),id(133)chr(f7)ptr(18302)bblk(9407),id(133)chr(f8)ptr(3024)bblk(9503),id(133)chr(f9)ptr(8288)bblk(9417),id(133)chr(fa)ptr(11078)bblk(9449),id(133)chr(fb)ptr(10658)bblk(9395),id(133)chr(fc)ptr(484)bblk(9433),id(133)chr(fd)ptr(534)bblk(9500),id(5)chr(fe)ptr(154)bblk(0),id(133)chr(ff)ptr(8338)bblk(9417))";

        let base_ptr = utils::parse_cow_ptr(base_ptr);
        let old_node = utils::parse_trie_node_256(old_node);
        let new_node = utils::parse_trie_node_256(new_node);

        assert_eq!(8, utils::count_full_ptrs(&old_node));
        assert_eq!(55, utils::count_full_ptrs(&new_node));

        let old_node_ptr = base_ptr.ptr().clone();
        let patch = TrieNodePatch::try_from_nodetype(old_node_ptr, &old_node, &new_node).unwrap();
        //assert_eq!(54, patch.ptr_diff.len());
        assert_eq!(55, patch.ptr_diff.len());

        println!("OLD PTR BACK COUNT: {}", count_back_ptrs(&old_node));
        println!("NEW PTR BACK COUNT: {}", count_back_ptrs(&new_node));

        assert_eq!(
            utils::count_full_ptrs(&new_node),
            patch.ptr_diff.len(),
            "new node ptrs len != patch node diff len"
        );
    }

    #[test]
    fn test_bug_fix_genesis_testnet_make_ptr_diff() {
        let base_ptr = "TrieCowPtr(a9d914ea8d70cbb097a3101f8d52a6d11a5100fa1ac41f3606be76bad00487be,id(134)chr(00)ptr(36)bblk(9507))";

        // Node 256 full with all character from 0 (00) to 255 (ff)
        // 248 are Backptr (133 to Node5) and 8 are not Backptr (id = 5)
        let old_node = "TrieNode256(path= ptrs=id(133)chr(00)ptr(452)bblk(9449),id(133)chr(01)ptr(3034)bblk(9449),id(133)chr(02)ptr(416)bblk(9498),id(133)chr(03)ptr(496)bblk(9437),id(133)chr(04)ptr(128)bblk(9460),id(133)chr(05)ptr(128)bblk(9467),id(133)chr(06)ptr(128)bblk(9429),id(133)chr(07)ptr(3084)bblk(9449),id(133)chr(08)ptr(128)bblk(9461),id(133)chr(09)ptr(422)bblk(9417),id(133)chr(0a)ptr(466)bblk(9498),id(133)chr(0b)ptr(2598)bblk(9425),id(133)chr(0c)ptr(128)bblk(9493),id(133)chr(0d)ptr(3048)bblk(9395),id(133)chr(0e)ptr(134)bblk(9469),id(133)chr(0f)ptr(3184)bblk(9449),id(133)chr(10)ptr(128)bblk(9225),id(133)chr(11)ptr(184)bblk(9469),id(133)chr(12)ptr(128)bblk(9506),id(133)chr(13)ptr(2944)bblk(9338),id(133)chr(14)ptr(516)bblk(9498),id(133)chr(15)ptr(128)bblk(9438),id(133)chr(16)ptr(178)bblk(9431),id(133)chr(17)ptr(178)bblk(9503),id(133)chr(18)ptr(140)bblk(9499),id(133)chr(19)ptr(672)bblk(9498),id(133)chr(1a)ptr(3284)bblk(9449),id(5)chr(1b)ptr(128)bblk(0),id(133)chr(1c)ptr(672)bblk(9407),id(133)chr(1d)ptr(722)bblk(9498),id(133)chr(1e)ptr(740)bblk(9335),id(133)chr(1f)ptr(128)bblk(9420),id(133)chr(20)ptr(678)bblk(9417),id(133)chr(21)ptr(772)bblk(9498),id(133)chr(22)ptr(3334)bblk(9449),id(133)chr(23)ptr(5910)bblk(9437),id(133)chr(24)ptr(128)bblk(9501),id(133)chr(25)ptr(5960)bblk(9437),id(133)chr(26)ptr(628)bblk(9401),id(133)chr(27)ptr(3384)bblk(9449),id(133)chr(28)ptr(3400)bblk(9407),id(133)chr(29)ptr(6010)bblk(9437),id(133)chr(2a)ptr(822)bblk(9498),id(5)chr(2b)ptr(178)bblk(0),id(133)chr(2c)ptr(872)bblk(9498),id(133)chr(2d)ptr(2648)bblk(9505),id(133)chr(2e)ptr(922)bblk(9498),id(133)chr(2f)ptr(6110)bblk(9437),id(133)chr(30)ptr(278)bblk(9453),id(5)chr(31)ptr(228)bblk(0),id(133)chr(32)ptr(928)bblk(9417),id(133)chr(33)ptr(972)bblk(9498),id(133)chr(34)ptr(178)bblk(9472),id(133)chr(35)ptr(1022)bblk(9498),id(133)chr(36)ptr(1072)bblk(9498),id(133)chr(37)ptr(1090)bblk(9335),id(133)chr(38)ptr(3484)bblk(9449),id(133)chr(39)ptr(178)bblk(9458),id(133)chr(3a)ptr(1190)bblk(9335),id(133)chr(3b)ptr(2826)bblk(9415),id(133)chr(3c)ptr(178)bblk(9455),id(133)chr(3d)ptr(2710)bblk(9476),id(133)chr(3e)ptr(2814)bblk(9497),id(133)chr(3f)ptr(3584)bblk(9449),id(133)chr(40)ptr(2648)bblk(9489),id(133)chr(41)ptr(1122)bblk(9498),id(133)chr(42)ptr(220)bblk(9354),id(133)chr(43)ptr(8996)bblk(9437),id(133)chr(44)ptr(228)bblk(9455),id(133)chr(45)ptr(1296)bblk(9335),id(133)chr(46)ptr(1172)bblk(9498),id(133)chr(47)ptr(1222)bblk(9498),id(133)chr(48)ptr(1272)bblk(9498),id(133)chr(49)ptr(178)bblk(9470),id(133)chr(4a)ptr(3862)bblk(9498),id(133)chr(4b)ptr(3740)bblk(9449),id(133)chr(4c)ptr(9252)bblk(9437),id(133)chr(4d)ptr(6336)bblk(9407),id(133)chr(4e)ptr(178)bblk(9468),id(133)chr(4f)ptr(3790)bblk(9449),id(133)chr(50)ptr(6386)bblk(9407),id(133)chr(51)ptr(3912)bblk(9498),id(133)chr(52)ptr(9302)bblk(9437),id(133)chr(53)ptr(290)bblk(9499),id(133)chr(54)ptr(134)bblk(9426),id(133)chr(55)ptr(3962)bblk(9498),id(133)chr(56)ptr(9018)bblk(9407),id(133)chr(57)ptr(178)bblk(9483),id(133)chr(58)ptr(11938)bblk(9437),id(133)chr(59)ptr(328)bblk(9174),id(133)chr(5a)ptr(3890)bblk(9449),id(5)chr(5b)ptr(278)bblk(0),id(133)chr(5c)ptr(3990)bblk(9449),id(133)chr(5d)ptr(4040)bblk(9449),id(133)chr(5e)ptr(228)bblk(9458),id(133)chr(5f)ptr(4012)bblk(9498),id(133)chr(60)ptr(4062)bblk(9498),id(5)chr(61)ptr(2864)bblk(0),id(133)chr(62)ptr(272)bblk(9486),id(133)chr(63)ptr(9174)bblk(9407),id(133)chr(64)ptr(4140)bblk(9449),id(133)chr(65)ptr(4162)bblk(9498),id(133)chr(66)ptr(4212)bblk(9498),id(133)chr(67)ptr(9274)bblk(9407),id(133)chr(68)ptr(4262)bblk(9498),id(133)chr(69)ptr(4312)bblk(9498),id(133)chr(6a)ptr(278)bblk(9463),id(133)chr(6b)ptr(278)bblk(9462),id(133)chr(6c)ptr(234)bblk(9242),id(133)chr(6d)ptr(4290)bblk(9449),id(133)chr(6e)ptr(328)bblk(9462),id(133)chr(6f)ptr(7816)bblk(9505),id(133)chr(70)ptr(12152)bblk(9335),id(133)chr(71)ptr(328)bblk(9327),id(133)chr(72)ptr(2864)bblk(9504),id(133)chr(73)ptr(4340)bblk(9449),id(133)chr(74)ptr(4362)bblk(9498),id(133)chr(75)ptr(278)bblk(9478),id(133)chr(76)ptr(234)bblk(9296),id(133)chr(77)ptr(4412)bblk(9498),id(133)chr(78)ptr(4462)bblk(9498),id(133)chr(79)ptr(4512)bblk(9498),id(133)chr(7a)ptr(5280)bblk(9473),id(5)chr(7b)ptr(2914)bblk(0),id(133)chr(7c)ptr(278)bblk(9490),id(133)chr(7d)ptr(14778)bblk(9437),id(133)chr(7e)ptr(2810)bblk(9476),id(133)chr(7f)ptr(4562)bblk(9498),id(133)chr(80)ptr(228)bblk(9495),id(133)chr(81)ptr(234)bblk(9477),id(133)chr(82)ptr(2864)bblk(9295),id(133)chr(83)ptr(4618)bblk(9498),id(133)chr(84)ptr(6720)bblk(9417),id(133)chr(85)ptr(9430)bblk(9407),id(133)chr(86)ptr(284)bblk(9500),id(133)chr(87)ptr(14928)bblk(9437),id(133)chr(88)ptr(278)bblk(9494),id(133)chr(89)ptr(2864)bblk(9399),id(133)chr(8a)ptr(4668)bblk(9498),id(133)chr(8b)ptr(5454)bblk(9504),id(133)chr(8c)ptr(2864)bblk(9450),id(133)chr(8d)ptr(4768)bblk(9498),id(133)chr(8e)ptr(278)bblk(9506),id(133)chr(8f)ptr(6906)bblk(9401),id(133)chr(90)ptr(278)bblk(9432),id(133)chr(91)ptr(284)bblk(9456),id(133)chr(92)ptr(328)bblk(9451),id(133)chr(93)ptr(378)bblk(9454),id(133)chr(94)ptr(7006)bblk(9401),id(133)chr(95)ptr(234)bblk(9491),id(133)chr(96)ptr(4874)bblk(9498),id(133)chr(97)ptr(4936)bblk(9498),id(133)chr(98)ptr(17714)bblk(9437),id(133)chr(99)ptr(378)bblk(9343),id(133)chr(9a)ptr(4790)bblk(9449),id(133)chr(9b)ptr(278)bblk(9427),id(133)chr(9c)ptr(7110)bblk(9395),id(133)chr(9d)ptr(4840)bblk(9449),id(133)chr(9e)ptr(4890)bblk(9449),id(133)chr(9f)ptr(4992)bblk(9498),id(133)chr(a0)ptr(2914)bblk(9471),id(133)chr(a1)ptr(620)bblk(9354),id(133)chr(a2)ptr(17864)bblk(9437),id(133)chr(a3)ptr(7570)bblk(9498),id(133)chr(a4)ptr(328)bblk(9445),id(133)chr(a5)ptr(434)bblk(9428),id(133)chr(a6)ptr(7156)bblk(9401),id(133)chr(a7)ptr(7620)bblk(9498),id(133)chr(a8)ptr(5380)bblk(9473),id(133)chr(a9)ptr(7220)bblk(9417),id(133)chr(aa)ptr(17914)bblk(9437),id(133)chr(ab)ptr(378)bblk(9482),id(133)chr(ac)ptr(7670)bblk(9498),id(133)chr(ad)ptr(378)bblk(9475),id(133)chr(ae)ptr(7270)bblk(9417),id(133)chr(af)ptr(6178)bblk(9390),id(133)chr(b0)ptr(384)bblk(9442),id(133)chr(b1)ptr(7320)bblk(9417),id(133)chr(b2)ptr(14952)bblk(9407),id(133)chr(b3)ptr(2864)bblk(9443),id(133)chr(b4)ptr(7720)bblk(9498),id(133)chr(b5)ptr(334)bblk(9502),id(133)chr(b6)ptr(328)bblk(9481),id(133)chr(b7)ptr(278)bblk(9488),id(133)chr(b8)ptr(384)bblk(9502),id(133)chr(b9)ptr(7770)bblk(9498),id(133)chr(ba)ptr(7820)bblk(9498),id(133)chr(bb)ptr(5196)bblk(9449),id(133)chr(bc)ptr(7870)bblk(9498),id(133)chr(bd)ptr(18064)bblk(9437),id(133)chr(be)ptr(328)bblk(9430),id(133)chr(bf)ptr(328)bblk(9412),id(133)chr(c0)ptr(378)bblk(9161),id(133)chr(c1)ptr(7556)bblk(9401),id(133)chr(c2)ptr(5246)bblk(9449),id(133)chr(c3)ptr(334)bblk(9465),id(133)chr(c4)ptr(378)bblk(9427),id(133)chr(c5)ptr(2920)bblk(9477),id(133)chr(c6)ptr(378)bblk(9420),id(133)chr(c7)ptr(4156)bblk(9338),id(133)chr(c8)ptr(18114)bblk(9437),id(133)chr(c9)ptr(18164)bblk(9437),id(133)chr(ca)ptr(2864)bblk(9506),id(133)chr(cb)ptr(5346)bblk(9449),id(133)chr(cc)ptr(5396)bblk(9449),id(133)chr(cd)ptr(7770)bblk(9417),id(133)chr(ce)ptr(7756)bblk(9401),id(133)chr(cf)ptr(7926)bblk(9498),id(133)chr(d0)ptr(328)bblk(9483),id(133)chr(d1)ptr(5446)bblk(9449),id(133)chr(d2)ptr(440)bblk(9499),id(5)chr(d3)ptr(2964)bblk(0),id(133)chr(d4)ptr(8026)bblk(9498),id(133)chr(d5)ptr(18486)bblk(9335),id(133)chr(d6)ptr(18320)bblk(9437),id(133)chr(d7)ptr(10108)bblk(9395),id(133)chr(d8)ptr(434)bblk(9479),id(133)chr(d9)ptr(5552)bblk(9449),id(133)chr(da)ptr(384)bblk(9432),id(133)chr(db)ptr(2974)bblk(9322),id(133)chr(dc)ptr(2920)bblk(9496),id(133)chr(dd)ptr(2970)bblk(9506),id(133)chr(de)ptr(434)bblk(9255),id(133)chr(df)ptr(8076)bblk(9498),id(133)chr(e0)ptr(434)bblk(9493),id(133)chr(e1)ptr(8242)bblk(9449),id(133)chr(e2)ptr(8292)bblk(9449),id(133)chr(e3)ptr(2916)bblk(9491),id(133)chr(e4)ptr(384)bblk(9466),id(133)chr(e5)ptr(484)bblk(9502),id(133)chr(e6)ptr(8126)bblk(9498),id(133)chr(e7)ptr(8176)bblk(9498),id(133)chr(e8)ptr(434)bblk(9495),id(133)chr(e9)ptr(434)bblk(9492),id(133)chr(ea)ptr(484)bblk(9414),id(133)chr(eb)ptr(434)bblk(9488),id(133)chr(ec)ptr(18470)bblk(9437),id(133)chr(ed)ptr(434)bblk(9467),id(133)chr(ee)ptr(484)bblk(9469),id(133)chr(ef)ptr(434)bblk(9459),id(133)chr(f0)ptr(2962)bblk(9434),id(133)chr(f1)ptr(434)bblk(9357),id(133)chr(f2)ptr(8226)bblk(9498),id(133)chr(f3)ptr(18152)bblk(9407),id(5)chr(f4)ptr(3020)bblk(0),id(133)chr(f5)ptr(484)bblk(9336),id(133)chr(f6)ptr(8182)bblk(9417),id(133)chr(f7)ptr(18302)bblk(9407),id(133)chr(f8)ptr(3024)bblk(9503),id(133)chr(f9)ptr(8288)bblk(9417),id(133)chr(fa)ptr(11078)bblk(9449),id(133)chr(fb)ptr(10658)bblk(9395),id(133)chr(fc)ptr(484)bblk(9433),id(133)chr(fd)ptr(534)bblk(9500),id(133)chr(fe)ptr(11128)bblk(9449),id(133)chr(ff)ptr(8338)bblk(9417))";

        // Node 256 full with all character from 0 (00) to 255 (ff)
        // 201 are Backptr (133 to Node5) and 55 are not Backptr (id = 5)
        let new_node = "TrieNode256(path= ptrs=id(133)chr(00)ptr(452)bblk(9449),id(133)chr(01)ptr(3034)bblk(9449),id(133)chr(02)ptr(416)bblk(9498),id(133)chr(03)ptr(496)bblk(9437),id(5)chr(04)ptr(78)bblk(0),id(133)chr(05)ptr(128)bblk(9467),id(133)chr(06)ptr(128)bblk(9429),id(133)chr(07)ptr(3084)bblk(9449),id(5)chr(08)ptr(172)bblk(0),id(5)chr(09)ptr(169)bblk(0),id(133)chr(0a)ptr(466)bblk(9498),id(5)chr(0b)ptr(84)bblk(0),id(133)chr(0c)ptr(128)bblk(9493),id(5)chr(0d)ptr(106)bblk(0),id(133)chr(0e)ptr(134)bblk(9469),id(133)chr(0f)ptr(3184)bblk(9449),id(5)chr(10)ptr(24)bblk(0),id(133)chr(11)ptr(184)bblk(9469),id(133)chr(12)ptr(128)bblk(9506),id(133)chr(13)ptr(2944)bblk(9338),id(133)chr(14)ptr(516)bblk(9498),id(133)chr(15)ptr(128)bblk(9438),id(133)chr(16)ptr(178)bblk(9431),id(133)chr(17)ptr(178)bblk(9503),id(5)chr(18)ptr(163)bblk(0),id(133)chr(19)ptr(672)bblk(9498),id(133)chr(1a)ptr(3284)bblk(9449),id(5)chr(1b)ptr(128)bblk(0),id(133)chr(1c)ptr(672)bblk(9407),id(5)chr(1d)ptr(142)bblk(0),id(133)chr(1e)ptr(740)bblk(9335),id(133)chr(1f)ptr(128)bblk(9420),id(133)chr(20)ptr(678)bblk(9417),id(133)chr(21)ptr(772)bblk(9498),id(133)chr(22)ptr(3334)bblk(9449),id(133)chr(23)ptr(5910)bblk(9437),id(133)chr(24)ptr(128)bblk(9501),id(5)chr(25)ptr(125)bblk(0),id(133)chr(26)ptr(628)bblk(9401),id(133)chr(27)ptr(3384)bblk(9449),id(133)chr(28)ptr(3400)bblk(9407),id(133)chr(29)ptr(6010)bblk(9437),id(133)chr(2a)ptr(822)bblk(9498),id(133)chr(2b)ptr(178)bblk(9507),id(133)chr(2c)ptr(872)bblk(9498),id(133)chr(2d)ptr(2648)bblk(9505),id(133)chr(2e)ptr(922)bblk(9498),id(133)chr(2f)ptr(6110)bblk(9437),id(133)chr(30)ptr(278)bblk(9453),id(133)chr(31)ptr(228)bblk(9507),id(133)chr(32)ptr(928)bblk(9417),id(133)chr(33)ptr(972)bblk(9498),id(133)chr(34)ptr(178)bblk(9472),id(133)chr(35)ptr(1022)bblk(9498),id(133)chr(36)ptr(1072)bblk(9498),id(133)chr(37)ptr(1090)bblk(9335),id(133)chr(38)ptr(3484)bblk(9449),id(5)chr(39)ptr(21)bblk(0),id(133)chr(3a)ptr(1190)bblk(9335),id(133)chr(3b)ptr(2826)bblk(9415),id(5)chr(3c)ptr(66)bblk(0),id(133)chr(3d)ptr(2710)bblk(9476),id(133)chr(3e)ptr(2814)bblk(9497),id(5)chr(3f)ptr(57)bblk(0),id(133)chr(40)ptr(2648)bblk(9489),id(5)chr(41)ptr(114)bblk(0),id(133)chr(42)ptr(220)bblk(9354),id(133)chr(43)ptr(8996)bblk(9437),id(133)chr(44)ptr(228)bblk(9455),id(133)chr(45)ptr(1296)bblk(9335),id(133)chr(46)ptr(1172)bblk(9498),id(133)chr(47)ptr(1222)bblk(9498),id(133)chr(48)ptr(1272)bblk(9498),id(5)chr(49)ptr(15)bblk(0),id(5)chr(4a)ptr(32)bblk(0),id(133)chr(4b)ptr(3740)bblk(9449),id(133)chr(4c)ptr(9252)bblk(9437),id(133)chr(4d)ptr(6336)bblk(9407),id(133)chr(4e)ptr(178)bblk(9468),id(133)chr(4f)ptr(3790)bblk(9449),id(5)chr(50)ptr(93)bblk(0),id(133)chr(51)ptr(3912)bblk(9498),id(133)chr(52)ptr(9302)bblk(9437),id(133)chr(53)ptr(290)bblk(9499),id(133)chr(54)ptr(134)bblk(9426),id(133)chr(55)ptr(3962)bblk(9498),id(133)chr(56)ptr(9018)bblk(9407),id(133)chr(57)ptr(178)bblk(9483),id(5)chr(58)ptr(184)bblk(0),id(133)chr(59)ptr(328)bblk(9174),id(133)chr(5a)ptr(3890)bblk(9449),id(5)chr(5b)ptr(11)bblk(0),id(133)chr(5c)ptr(3990)bblk(9449),id(5)chr(5d)ptr(60)bblk(0),id(133)chr(5e)ptr(228)bblk(9458),id(133)chr(5f)ptr(4012)bblk(9498),id(133)chr(60)ptr(4062)bblk(9498),id(5)chr(61)ptr(187)bblk(0),id(5)chr(62)ptr(54)bblk(0),id(133)chr(63)ptr(9174)bblk(9407),id(5)chr(64)ptr(27)bblk(0),id(5)chr(65)ptr(18)bblk(0),id(5)chr(66)ptr(119)bblk(0),id(133)chr(67)ptr(9274)bblk(9407),id(133)chr(68)ptr(4262)bblk(9498),id(133)chr(69)ptr(4312)bblk(9498),id(5)chr(6a)ptr(160)bblk(0),id(133)chr(6b)ptr(278)bblk(9462),id(133)chr(6c)ptr(234)bblk(9242),id(5)chr(6d)ptr(139)bblk(0),id(5)chr(6e)ptr(4)bblk(0),id(133)chr(6f)ptr(7816)bblk(9505),id(133)chr(70)ptr(12152)bblk(9335),id(133)chr(71)ptr(328)bblk(9327),id(5)chr(72)ptr(178)bblk(0),id(133)chr(73)ptr(4340)bblk(9449),id(133)chr(74)ptr(4362)bblk(9498),id(133)chr(75)ptr(278)bblk(9478),id(133)chr(76)ptr(234)bblk(9296),id(133)chr(77)ptr(4412)bblk(9498),id(5)chr(78)ptr(63)bblk(0),id(133)chr(79)ptr(4512)bblk(9498),id(133)chr(7a)ptr(5280)bblk(9473),id(133)chr(7b)ptr(2914)bblk(9507),id(133)chr(7c)ptr(278)bblk(9490),id(133)chr(7d)ptr(14778)bblk(9437),id(133)chr(7e)ptr(2810)bblk(9476),id(133)chr(7f)ptr(4562)bblk(9498),id(133)chr(80)ptr(228)bblk(9495),id(5)chr(81)ptr(75)bblk(0),id(133)chr(82)ptr(2864)bblk(9295),id(133)chr(83)ptr(4618)bblk(9498),id(133)chr(84)ptr(6720)bblk(9417),id(5)chr(85)ptr(145)bblk(0),id(133)chr(86)ptr(284)bblk(9500),id(133)chr(87)ptr(14928)bblk(9437),id(133)chr(88)ptr(278)bblk(9494),id(133)chr(89)ptr(2864)bblk(9399),id(133)chr(8a)ptr(4668)bblk(9498),id(133)chr(8b)ptr(5454)bblk(9504),id(133)chr(8c)ptr(2864)bblk(9450),id(133)chr(8d)ptr(4768)bblk(9498),id(133)chr(8e)ptr(278)bblk(9506),id(133)chr(8f)ptr(6906)bblk(9401),id(133)chr(90)ptr(278)bblk(9432),id(133)chr(91)ptr(284)bblk(9456),id(5)chr(92)ptr(175)bblk(0),id(5)chr(93)ptr(122)bblk(0),id(133)chr(94)ptr(7006)bblk(9401),id(5)chr(95)ptr(87)bblk(0),id(5)chr(96)ptr(42)bblk(0),id(133)chr(97)ptr(4936)bblk(9498),id(133)chr(98)ptr(17714)bblk(9437),id(133)chr(99)ptr(378)bblk(9343),id(133)chr(9a)ptr(4790)bblk(9449),id(133)chr(9b)ptr(278)bblk(9427),id(133)chr(9c)ptr(7110)bblk(9395),id(133)chr(9d)ptr(4840)bblk(9449),id(133)chr(9e)ptr(4890)bblk(9449),id(133)chr(9f)ptr(4992)bblk(9498),id(133)chr(a0)ptr(2914)bblk(9471),id(5)chr(a1)ptr(72)bblk(0),id(133)chr(a2)ptr(17864)bblk(9437),id(133)chr(a3)ptr(7570)bblk(9498),id(5)chr(a4)ptr(81)bblk(0),id(5)chr(a5)ptr(38)bblk(0),id(133)chr(a6)ptr(7156)bblk(9401),id(133)chr(a7)ptr(7620)bblk(9498),id(133)chr(a8)ptr(5380)bblk(9473),id(133)chr(a9)ptr(7220)bblk(9417),id(133)chr(aa)ptr(17914)bblk(9437),id(133)chr(ab)ptr(378)bblk(9482),id(5)chr(ac)ptr(181)bblk(0),id(133)chr(ad)ptr(378)bblk(9475),id(133)chr(ae)ptr(7270)bblk(9417),id(5)chr(af)ptr(35)bblk(0),id(133)chr(b0)ptr(384)bblk(9442),id(133)chr(b1)ptr(7320)bblk(9417),id(133)chr(b2)ptr(14952)bblk(9407),id(133)chr(b3)ptr(2864)bblk(9443),id(133)chr(b4)ptr(7720)bblk(9498),id(133)chr(b5)ptr(334)bblk(9502),id(133)chr(b6)ptr(328)bblk(9481),id(133)chr(b7)ptr(278)bblk(9488),id(133)chr(b8)ptr(384)bblk(9502),id(133)chr(b9)ptr(7770)bblk(9498),id(133)chr(ba)ptr(7820)bblk(9498),id(5)chr(bb)ptr(151)bblk(0),id(133)chr(bc)ptr(7870)bblk(9498),id(133)chr(bd)ptr(18064)bblk(9437),id(133)chr(be)ptr(328)bblk(9430),id(5)chr(bf)ptr(48)bblk(0),id(5)chr(c0)ptr(90)bblk(0),id(133)chr(c1)ptr(7556)bblk(9401),id(133)chr(c2)ptr(5246)bblk(9449),id(5)chr(c3)ptr(157)bblk(0),id(133)chr(c4)ptr(378)bblk(9427),id(133)chr(c5)ptr(2920)bblk(9477),id(5)chr(c6)ptr(45)bblk(0),id(133)chr(c7)ptr(4156)bblk(9338),id(133)chr(c8)ptr(18114)bblk(9437),id(133)chr(c9)ptr(18164)bblk(9437),id(133)chr(ca)ptr(2864)bblk(9506),id(5)chr(cb)ptr(131)bblk(0),id(133)chr(cc)ptr(5396)bblk(9449),id(133)chr(cd)ptr(7770)bblk(9417),id(133)chr(ce)ptr(7756)bblk(9401),id(5)chr(cf)ptr(136)bblk(0),id(133)chr(d0)ptr(328)bblk(9483),id(5)chr(d1)ptr(111)bblk(0),id(133)chr(d2)ptr(440)bblk(9499),id(5)chr(d3)ptr(1)bblk(0),id(133)chr(d4)ptr(8026)bblk(9498),id(133)chr(d5)ptr(18486)bblk(9335),id(133)chr(d6)ptr(18320)bblk(9437),id(133)chr(d7)ptr(10108)bblk(9395),id(133)chr(d8)ptr(434)bblk(9479),id(133)chr(d9)ptr(5552)bblk(9449),id(133)chr(da)ptr(384)bblk(9432),id(133)chr(db)ptr(2974)bblk(9322),id(133)chr(dc)ptr(2920)bblk(9496),id(5)chr(dd)ptr(148)bblk(0),id(133)chr(de)ptr(434)bblk(9255),id(133)chr(df)ptr(8076)bblk(9498),id(133)chr(e0)ptr(434)bblk(9493),id(133)chr(e1)ptr(8242)bblk(9449),id(133)chr(e2)ptr(8292)bblk(9449),id(133)chr(e3)ptr(2916)bblk(9491),id(133)chr(e4)ptr(384)bblk(9466),id(133)chr(e5)ptr(484)bblk(9502),id(133)chr(e6)ptr(8126)bblk(9498),id(133)chr(e7)ptr(8176)bblk(9498),id(133)chr(e8)ptr(434)bblk(9495),id(133)chr(e9)ptr(434)bblk(9492),id(133)chr(ea)ptr(484)bblk(9414),id(5)chr(eb)ptr(100)bblk(0),id(5)chr(ec)ptr(51)bblk(0),id(133)chr(ed)ptr(434)bblk(9467),id(133)chr(ee)ptr(484)bblk(9469),id(133)chr(ef)ptr(434)bblk(9459),id(133)chr(f0)ptr(2962)bblk(9434),id(133)chr(f1)ptr(434)bblk(9357),id(133)chr(f2)ptr(8226)bblk(9498),id(133)chr(f3)ptr(18152)bblk(9407),id(5)chr(f4)ptr(8)bblk(0),id(133)chr(f5)ptr(484)bblk(9336),id(133)chr(f6)ptr(8182)bblk(9417),id(133)chr(f7)ptr(18302)bblk(9407),id(133)chr(f8)ptr(3024)bblk(9503),id(133)chr(f9)ptr(8288)bblk(9417),id(133)chr(fa)ptr(11078)bblk(9449),id(133)chr(fb)ptr(10658)bblk(9395),id(133)chr(fc)ptr(484)bblk(9433),id(133)chr(fd)ptr(534)bblk(9500),id(5)chr(fe)ptr(154)bblk(0),id(133)chr(ff)ptr(8338)bblk(9417))";

        let base_ptr = utils::parse_cow_ptr(base_ptr);
        let old_node = utils::parse_trie_node_256(old_node);
        let new_node = utils::parse_trie_node_256(new_node);

        let old_node_ptr = base_ptr.ptr().clone();
        let diff = TrieNodePatch::make_ptr_diff(&old_node_ptr, old_node.ptrs(), new_node.ptrs());
        assert_eq!(55, diff.len());
    }

    #[test]
    fn trie_node_patch_make_ptr_diff_case1() {
        // input:
        //  - no old_ptrs
        //  - a new_ptr that is empty
        // output:
        //  - no diff

        let old_node_ptr = TriePtr::new_backptr(TrieNodeID::Patch as u8, 0x00, 0, 1);
        let old_ptrs = [];
        let new_ptrs = [TriePtr::new(TrieNodeID::Empty as u8, 0x00, 0)];

        let diff = TrieNodePatch::make_ptr_diff(&old_node_ptr, &old_ptrs, &new_ptrs);
        assert_eq!(0, diff.len());
    }

    #[test]
    fn trie_node_patch_make_ptr_diff_case2() {
        // input:
        //  - no old_ptrs
        //  - 2 valid new_ptrs (one normal node and one back-pointer)
        // output:
        //  - 2 diff

        let old_node_ptr = TriePtr::new_backptr(TrieNodeID::Patch as u8, 0x00, 0, 1);
        let old_ptrs = [];
        let new_ptrs = [
            TriePtr::new(TrieNodeID::Node4 as u8, 0x00, 0),
            TriePtr::new_backptr(TrieNodeID::Node4 as u8, 0x01, 0, 1),
        ];

        let diff = TrieNodePatch::make_ptr_diff(&old_node_ptr, &old_ptrs, &new_ptrs);
        assert_eq!(2, diff.len());
        assert_eq!(TriePtr::new(TrieNodeID::Node4 as u8, 0x00, 0), diff[0]);
        assert_eq!(
            TriePtr::new_backptr(TrieNodeID::Node4 as u8, 0x01, 0, 1),
            diff[1]
        );
    }

    #[test]
    fn trie_node_patch_make_ptr_diff_case3() {
        // input:
        //  - ith old_ptr is not a back-pointer
        //  - ith new_ptr is a back-pointer and back_block match the old_node_ptr back_block
        //     and when normalized match the old pointer
        // output:
        //  - no diff

        let old_node_ptr = TriePtr::new_backptr(TrieNodeID::Patch as u8, 0x00, 0, 1);
        let old_ptrs = [TriePtr::new(TrieNodeID::Node4 as u8, 0x00, 0)];
        let new_ptrs = [TriePtr::new_backptr(TrieNodeID::Node4 as u8, 0x00, 0, 1)];

        let diff = TrieNodePatch::make_ptr_diff(&old_node_ptr, &old_ptrs, &new_ptrs);
        assert_eq!(0, diff.len());
    }

    #[test]
    fn trie_node_patch_make_ptr_diff_case4() {
        // input:
        //  - ith old_ptr is not a back-pointer
        //  - ith new_ptr is a back-pointer and back_block matches the old_node_ptr back_block
        //     and when normalized NOT matches the old pointer
        // output:
        //  - 1 diff

        let old_node_ptr = TriePtr::new_backptr(TrieNodeID::Patch as u8, 0x00, 0, 1);
        let old_ptrs = [TriePtr::new(TrieNodeID::Node4 as u8, 0x00, 0)];
        let new_ptrs = [TriePtr::new_backptr(TrieNodeID::Node4 as u8, 0x00, 100, 1)];

        let diff = TrieNodePatch::make_ptr_diff(&old_node_ptr, &old_ptrs, &new_ptrs);
        assert_eq!(1, diff.len());
        assert_eq!(
            TriePtr::new_backptr(TrieNodeID::Node4 as u8, 0x00, 100, 1),
            diff[0]
        );
    }

    #[test]
    fn trie_node_patch_make_ptr_diff_case5() {
        // input:
        //  - ith `old_ptr` is not a back-pointer
        //  - ith `new_ptr` is a back-pointer and back_block NOT matches the `old_node_ptr` back_block
        //      and it NOT matches the `old_ptr`
        // output:
        //  - 1 diff

        let old_node_ptr = TriePtr::new_backptr(TrieNodeID::Patch as u8, 0x00, 0, 1);
        let old_ptrs = [TriePtr::new(TrieNodeID::Node4 as u8, 0x00, 0)];
        let new_ptrs = [TriePtr::new_backptr(
            TrieNodeID::Node4 as u8,
            0x00,
            100,
            100,
        )];

        let diff = TrieNodePatch::make_ptr_diff(&old_node_ptr, &old_ptrs, &new_ptrs);
        assert_eq!(1, diff.len());
        assert_eq!(
            TriePtr::new_backptr(TrieNodeID::Node4 as u8, 0x00, 100, 100),
            diff[0]
        );
    }

    #[test]
    fn trie_node_patch_make_ptr_diff_case6() {
        // input:
        //  - ith `old_ptr` is a back-pointer
        //  - ith `new_ptr` is a back-pointer and it matches the `old_ptr`
        // output:
        //  - no diff

        let old_node_ptr = TriePtr::new_backptr(TrieNodeID::Patch as u8, 0x00, 0, 1);
        let old_ptrs = [TriePtr::new_backptr(TrieNodeID::Node4 as u8, 0x00, 0x00, 2)];
        let new_ptrs = [TriePtr::new_backptr(TrieNodeID::Node4 as u8, 0x00, 0x00, 2)];

        let diff = TrieNodePatch::make_ptr_diff(&old_node_ptr, &old_ptrs, &new_ptrs);
        assert_eq!(0, diff.len());
    }

    #[test]
    fn trie_node_patch_make_ptr_diff_case7() {
        // input:
        //  - ith `old_ptr` is NOT a back-pointer
        //  - ith `new_ptr` is NOT a back-pointer and it matches the `old_ptr`
        // output:
        //  - 1 diff

        let old_node_ptr = TriePtr::new_backptr(TrieNodeID::Patch as u8, 0x00, 0, 1);
        let old_ptrs = [TriePtr::new(TrieNodeID::Node4 as u8, 0x00, 0x00)];
        let new_ptrs = [TriePtr::new(TrieNodeID::Node4 as u8, 0x00, 0x00)];

        let diff = TrieNodePatch::make_ptr_diff(&old_node_ptr, &old_ptrs, &new_ptrs);
        assert_eq!(1, diff.len());
        assert_eq!(TriePtr::new(TrieNodeID::Node4 as u8, 0x00, 0x00), diff[0]);
    }
}
