use stacks_common::{types::chainstate::{BlockHeaderHash, TrieHash}, test_debug};
use stacks_marf::{storage::TrieStorageConnection, node::{TriePtr, TrieNodeID, TrieNodeType, TrieNode4, TrieNode16, TrieNode48, TrieNode256, TrieNode, is_backptr}, TrieLeaf, TrieDb, TrieHashExtension, MarfTrieId, trie::Trie};

mod cache;
mod node;

pub fn make_node4_path<TrieDB>(
    s: &mut TrieStorageConnection<BlockHeaderHash, TrieDB>,
    path_segments: &Vec<(Vec<u8>, u8)>,
    leaf_data: Vec<u8>,
) -> (Vec<TrieNodeType>, Vec<TriePtr>, Vec<TrieHash>) 
where
    TrieDB: TrieDb
{
    make_node_path(s, TrieNodeID::Node4 as u8, path_segments, leaf_data)
}

pub fn make_node_path<TrieDB>(
    s: &mut TrieStorageConnection<BlockHeaderHash, TrieDB>,
    node_id: u8,
    path_segments: &Vec<(Vec<u8>, u8)>,
    leaf_data: Vec<u8>,
) -> (Vec<TrieNodeType>, Vec<TriePtr>, Vec<TrieHash>) 
where
    TrieDB: TrieDb
{
    // make a fully-fleshed-out path of node's to a leaf
    let root_ptr = s.root_ptr();
    let root = TrieNode256::new(&path_segments[0].0);
    let root_hash = TrieHash::from_data(&[0u8; 32]); // don't care about this in this test
    s.write_node(root_ptr, &root, root_hash.clone()).unwrap();

    let mut parent = TrieNodeType::Node256(Box::new(root));
    let mut parent_ptr = root_ptr;

    let mut nodes = vec![];
    let mut node_ptrs = vec![];
    let mut hashes = vec![];
    let mut seg_id = 0;

    for i in 0..path_segments.len() - 1 {
        let path_segment = &path_segments[i + 1].0;
        let chr = path_segments[i].1;
        let node_ptr = s.last_ptr().unwrap();

        let node = match TrieNodeID::from_u8(node_id).unwrap() {
            TrieNodeID::Node4 => TrieNodeType::Node4(TrieNode4::new(path_segment)),
            TrieNodeID::Node16 => TrieNodeType::Node16(TrieNode16::new(path_segment)),
            TrieNodeID::Node48 => TrieNodeType::Node48(Box::new(TrieNode48::new(path_segment))),
            TrieNodeID::Node256 => TrieNodeType::Node256(Box::new(TrieNode256::new(path_segment))),
            _ => panic!("invalid node ID"),
        };

        s.write_nodetype(
            node_ptr,
            &node,
            TrieHash::from_data(&[(seg_id + 1) as u8; 32]),
        )
        .unwrap();

        // update parent
        match parent {
            TrieNodeType::Node256(ref mut data) => {
                assert!(data.insert(&TriePtr::new(node_id, chr, node_ptr as u32)))
            }
            TrieNodeType::Node48(ref mut data) => {
                assert!(data.insert(&TriePtr::new(node_id, chr, node_ptr as u32)))
            }
            TrieNodeType::Node16(ref mut data) => {
                assert!(data.insert(&TriePtr::new(node_id, chr, node_ptr as u32)))
            }
            TrieNodeType::Node4(ref mut data) => {
                assert!(data.insert(&TriePtr::new(node_id, chr, node_ptr as u32)))
            }
            TrieNodeType::Leaf(_) => panic!("can't insert into leaf"),
        };

        s.write_nodetype(
            parent_ptr,
            &parent,
            TrieHash::from_data(&[seg_id as u8; 32]),
        )
        .unwrap();

        nodes.push(parent.clone());
        node_ptrs.push(TriePtr::new(node_id, chr, node_ptr as u32));
        hashes.push(TrieHash::from_data(&[(seg_id + 1) as u8; 32]));

        parent = node;
        parent_ptr = node_ptr;

        seg_id += 1;
    }

    // add a leaf at the end
    let child = TrieLeaf::new(&path_segments[path_segments.len() - 1].0, &leaf_data);
    let child_chr = path_segments[path_segments.len() - 1].1;
    let child_ptr = s.last_ptr().unwrap();
    s.write_node(
        child_ptr,
        &child,
        TrieHash::from_data(&[(seg_id + 1) as u8; 32]),
    )
    .unwrap();

    // update parent
    match parent {
        TrieNodeType::Node256(ref mut data) => assert!(data.insert(&TriePtr::new(
            TrieNodeID::Leaf as u8,
            child_chr,
            child_ptr as u32
        ))),
        TrieNodeType::Node48(ref mut data) => assert!(data.insert(&TriePtr::new(
            TrieNodeID::Leaf as u8,
            child_chr,
            child_ptr as u32
        ))),
        TrieNodeType::Node16(ref mut data) => assert!(data.insert(&TriePtr::new(
            TrieNodeID::Leaf as u8,
            child_chr,
            child_ptr as u32
        ))),
        TrieNodeType::Node4(ref mut data) => assert!(data.insert(&TriePtr::new(
            TrieNodeID::Leaf as u8,
            child_chr,
            child_ptr as u32
        ))),
        TrieNodeType::Leaf(_) => panic!("can't insert into leaf"),
    };

    s.write_nodetype(
        parent_ptr,
        &parent,
        TrieHash::from_data(&[(seg_id) as u8; 32]),
    )
    .unwrap();

    nodes.push(parent.clone());
    node_ptrs.push(TriePtr::new(
        TrieNodeID::Leaf as u8,
        child_chr,
        child_ptr as u32,
    ));
    hashes.push(TrieHash::from_data(&[(seg_id + 1) as u8; 32]));

    (nodes, node_ptrs, hashes)
}

/// Print out a trie to stderr
pub fn dump_trie<Id, TrieDB>(s: &mut TrieStorageConnection<Id, TrieDB>)
where
    Id: MarfTrieId,
    TrieDB: TrieDb
{
    test_debug!("\n----- BEGIN TRIE ------");

    fn space(cnt: usize) -> String {
        let mut ret = vec![];
        for _ in 0..cnt {
            ret.push(" ".to_string());
        }
        ret.join("")
    }

    let root_ptr = s.root_ptr();
    let mut frontier: Vec<(TrieNodeType, TrieHash, usize)> = vec![];
    let (root, root_hash) = Trie::read_root(s).unwrap();
    frontier.push((root, root_hash, 0));

    while frontier.len() > 0 {
        let (next, next_hash, depth) = frontier.pop().unwrap();
        let (ptrs, path_len) = match next {
            TrieNodeType::Leaf(ref leaf_data) => {
                test_debug!("{}{} {:?}", &space(depth), next_hash, leaf_data);
                (vec![], leaf_data.path.len())
            }
            TrieNodeType::Node4(ref data) => {
                test_debug!("{}{} {:?}", &space(depth), next_hash, data);
                (data.ptrs.to_vec(), data.path.len())
            }
            TrieNodeType::Node16(ref data) => {
                test_debug!("{}{} {:?}", &space(depth), next_hash, data);
                (data.ptrs.to_vec(), data.path.len())
            }
            TrieNodeType::Node48(ref data) => {
                test_debug!("{}{} {:?}", &space(depth), next_hash, data);
                (data.ptrs.to_vec(), data.path.len())
            }
            TrieNodeType::Node256(ref data) => {
                test_debug!("{}{} {:?}", &space(depth), next_hash, data);
                (data.ptrs.to_vec(), data.path.len())
            }
        };
        for ptr in ptrs.iter() {
            if ptr.id() == TrieNodeID::Empty as u8 {
                continue;
            }
            if !is_backptr(ptr.id()) {
                let (child_node, child_hash) = s.read_nodetype(ptr).unwrap();
                frontier.push((child_node, child_hash, depth + path_len + 1));
            }
        }
    }

    test_debug!("----- END TRIE ------\n");
}