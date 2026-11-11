//! Fixed-capacity model of the NT object-manager namespace.
//!
//! The namespace is a tree of named object nodes rooted at `\`. Nodes occupy
//! slots of a const-sized table, so creation and lookup never allocate.
//! Lookups are ASCII case-insensitive, as with `OBJ_CASE_INSENSITIVE`, while
//! each node keeps the spelling it was created with.
//!
//! A [`NodeId`] pairs a slot index with the generation the slot had when its
//! node was created. Removing a node advances the slot's generation, so an
//! identifier kept past removal is rejected with [`Error::InvalidHandle`]
//! instead of naming whatever node later reuses the slot. A slot whose
//! generation cannot advance any further is retired permanently rather than
//! wrapped, so no identifier can ever match a different node in it.

use crate::nt::ObjectType;
use crate::{Error, Result};

/// Longest single path component, in bytes.
pub const MAX_NAME_LENGTH: usize = 64;

/// Deepest path, in components, that the namespace accepts.
///
/// A path with more components than this is rejected as [`Error::InvalidName`]
/// by both `create` and `lookup`.
pub const MAX_DEPTH: usize = 16;

/// Slot index of the root directory.
const ROOT: usize = 0;

/// Generation of the root directory. The root is never removed, so its
/// generation never changes and [`NodeId::ROOT`] stays valid forever.
const ROOT_GENERATION: u32 = 0;

/// Name stored for the root directory.
const ROOT_NAME: &[u8] = b"\\";

/// Identifier of a namespace node, valid only for the namespace that produced
/// it and only until that node is removed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeId {
    index: usize,
    generation: u32,
}

impl NodeId {
    /// Identifier of the root directory `\`, which is always present.
    pub const ROOT: Self = Self {
        index: ROOT,
        generation: ROOT_GENERATION,
    };
}

#[derive(Clone, Copy, Debug)]
struct Node {
    name: [u8; MAX_NAME_LENGTH],
    name_length: usize,
    parent: usize,
    object_type: ObjectType,
    present: bool,
    /// Generation carried by identifiers of the node that occupies this slot.
    /// Advanced by `remove`, so earlier identifiers no longer match.
    generation: u32,
    /// Set when `generation` reached its maximum and cannot advance. The slot
    /// is then never reused, so the generation never wraps.
    retired: bool,
}

impl Node {
    const VACANT: Self = Self {
        name: [0; MAX_NAME_LENGTH],
        name_length: 0,
        parent: ROOT,
        object_type: ObjectType::Directory,
        present: false,
        generation: 0,
        retired: false,
    };

    /// Build a live node from a name that has already been validated.
    fn new(name: &[u8], parent: usize, object_type: ObjectType, generation: u32) -> Self {
        let mut stored = [0u8; MAX_NAME_LENGTH];
        stored[..name.len()].copy_from_slice(name);
        Self {
            name: stored,
            name_length: name.len(),
            parent,
            object_type,
            present: true,
            generation,
            retired: false,
        }
    }

    fn name(&self) -> &[u8] {
        &self.name[..self.name_length]
    }
}

/// A fixed-capacity NT object namespace with `N` node slots.
///
/// The root directory occupies slot 0 and counts against `N`, so at most
/// `N - 1` further objects can exist at once. With `N == 0` no lookup
/// succeeds and every `create` fails.
#[derive(Clone, Copy, Debug)]
pub struct ObjectNamespace<const N: usize> {
    nodes: [Node; N],
}

impl<const N: usize> Default for ObjectNamespace<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> ObjectNamespace<N> {
    /// Construct a namespace holding only the root directory `\`.
    pub const fn new() -> Self {
        let mut nodes = [Node::VACANT; N];
        if N > 0 {
            nodes[ROOT] = Node {
                name: name_array(ROOT_NAME),
                name_length: ROOT_NAME.len(),
                parent: ROOT,
                object_type: ObjectType::Directory,
                present: true,
                generation: ROOT_GENERATION,
                retired: false,
            };
        }
        Self { nodes }
    }

    /// Create an object at an absolute path and return its identifier.
    ///
    /// The parent directory must already exist. Names are compared
    /// case-insensitively, so creating a name that differs only by case from a
    /// sibling fails with [`Error::AlreadyExists`].
    ///
    /// Errors:
    /// - [`Error::InvalidName`]: the path is malformed (see [`lookup`](Self::lookup)),
    ///   or it is the root itself, which is never created.
    /// - [`Error::NotFound`]: the parent directory does not exist.
    /// - [`Error::InvalidState`]: the parent is not a directory.
    /// - [`Error::AlreadyExists`]: a sibling with the same name exists.
    /// - [`Error::TableFull`]: no free node slot remains.
    pub fn create(&mut self, path: &str, object_type: ObjectType) -> Result<NodeId> {
        let depth = check_path(path)?;
        if depth == 0 {
            return Err(Error::AlreadyExists);
        }

        // Every component is validated, so the last `\` separates the parent
        // path from the new name. The parent of a top-level name is the root.
        let separator = path.rfind('\\').ok_or(Error::InvalidName)?;
        let parent_path = &path[..separator.max(1)];
        let name = &path.as_bytes()[separator + 1..];

        let parent = self.lookup(parent_path)?.index;
        if self.node(parent)?.object_type != ObjectType::Directory {
            return Err(Error::InvalidState);
        }
        if self.child(parent, name).is_some() {
            return Err(Error::AlreadyExists);
        }

        let slot = self
            .nodes
            .iter()
            .position(|node| !node.present && !node.retired)
            .ok_or(Error::TableFull)?;
        let generation = self.nodes[slot].generation;
        self.nodes[slot] = Node::new(name, parent, object_type, generation);
        Ok(NodeId {
            index: slot,
            generation,
        })
    }

    /// Resolve an absolute path to its node.
    ///
    /// A path must begin with `\`, and its components must be non-empty, at
    /// most [`MAX_NAME_LENGTH`] ASCII bytes, and free of NUL. Components are
    /// separated by `\`, so a trailing or doubled separator is rejected. The
    /// path `\` names the root. At most [`MAX_DEPTH`] components are accepted.
    ///
    /// Errors: [`Error::InvalidName`] for a malformed path, and
    /// [`Error::NotFound`] when a component does not resolve.
    pub fn lookup(&self, path: &str) -> Result<NodeId> {
        check_path(path)?;
        let body = path.strip_prefix('\\').ok_or(Error::InvalidName)?;
        let mut current = ROOT;
        if !body.is_empty() {
            for component in body.split('\\') {
                current = self
                    .child(current, component.as_bytes())
                    .ok_or(Error::NotFound)?;
            }
        }
        self.node(current)?;
        Ok(self.id_of(current))
    }

    /// Remove a node, freeing its slot for reuse under a new generation.
    ///
    /// Every identifier of the removed node becomes stale. If the slot's
    /// generation is already at its maximum, the slot is retired instead and
    /// is never used again.
    ///
    /// Errors:
    /// - [`Error::PermissionDenied`]: the node is the root, which is protected.
    /// - [`Error::InvalidHandle`]: the identifier is stale or foreign.
    /// - [`Error::InvalidState`]: the node is a directory that still has children.
    pub fn remove(&mut self, node: NodeId) -> Result<()> {
        if node.index == ROOT {
            return Err(Error::PermissionDenied);
        }
        let index = self.live(node)?;
        if self
            .nodes
            .iter()
            .any(|child| child.present && child.parent == index)
        {
            return Err(Error::InvalidState);
        }
        let slot = &mut self.nodes[index];
        let (generation, retired) = match slot.generation.checked_add(1) {
            Some(next) => (next, false),
            None => (slot.generation, true),
        };
        *slot = Node {
            generation,
            retired,
            ..Node::VACANT
        };
        Ok(())
    }

    /// The name of a node, in the case it was created with.
    ///
    /// The root is named `\`.
    ///
    /// Errors: [`Error::InvalidHandle`] for a stale or foreign identifier.
    pub fn name(&self, node: NodeId) -> Result<&str> {
        let index = self.live(node)?;
        core::str::from_utf8(self.nodes[index].name()).map_err(|_| Error::InvalidInput)
    }

    /// The object type of a node.
    ///
    /// Errors: [`Error::InvalidHandle`] for a stale or foreign identifier.
    pub fn object_type(&self, node: NodeId) -> Result<ObjectType> {
        let index = self.live(node)?;
        Ok(self.nodes[index].object_type)
    }

    /// Check an identifier against its slot and return the slot index.
    fn live(&self, node: NodeId) -> Result<usize> {
        match self.nodes.get(node.index) {
            Some(slot) if slot.present && slot.generation == node.generation => Ok(node.index),
            _ => Err(Error::InvalidHandle),
        }
    }

    /// The identifier of the live node in slot `index`.
    fn id_of(&self, index: usize) -> NodeId {
        NodeId {
            index,
            generation: self.nodes[index].generation,
        }
    }

    fn node(&self, index: usize) -> Result<&Node> {
        self.nodes
            .get(index)
            .filter(|node| node.present)
            .ok_or(Error::NotFound)
    }

    /// Find a live child of `parent` whose name matches case-insensitively.
    fn child(&self, parent: usize, name: &[u8]) -> Option<usize> {
        self.nodes
            .iter()
            .enumerate()
            .find(|(index, node)| {
                *index != ROOT
                    && node.present
                    && node.parent == parent
                    && node.name().eq_ignore_ascii_case(name)
            })
            .map(|(index, _)| index)
    }
}

/// Validate an absolute path and return its component count.
///
/// The root path `\` has zero components.
fn check_path(path: &str) -> Result<usize> {
    let body = path.strip_prefix('\\').ok_or(Error::InvalidName)?;
    if body.is_empty() {
        return Ok(0);
    }
    let mut depth = 0usize;
    for component in body.split('\\') {
        check_component(component.as_bytes())?;
        depth += 1;
    }
    if depth > MAX_DEPTH {
        return Err(Error::InvalidName);
    }
    Ok(depth)
}

fn check_component(name: &[u8]) -> Result<()> {
    if name.is_empty() || name.len() > MAX_NAME_LENGTH || !name.is_ascii() || name.contains(&0) {
        return Err(Error::InvalidName);
    }
    Ok(())
}

/// Copy a name into a fixed buffer in a const context.
const fn name_array(name: &[u8]) -> [u8; MAX_NAME_LENGTH] {
    let mut stored = [0u8; MAX_NAME_LENGTH];
    let mut index = 0;
    while index < name.len() {
        stored[index] = name[index];
        index += 1;
    }
    stored
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build `\aaa...` with `length` components-bytes in a caller buffer.
    fn path_with_component(buffer: &mut [u8; 80], length: usize) -> &str {
        buffer[0] = b'\\';
        for byte in &mut buffer[1..=length] {
            *byte = b'a';
        }
        core::str::from_utf8(&buffer[..=length]).unwrap()
    }

    #[test]
    fn root_is_a_protected_directory_named_backslash() {
        let mut ns = ObjectNamespace::<4>::new();
        assert_eq!(ns.lookup("\\"), Ok(NodeId::ROOT));
        assert_eq!(ns.name(NodeId::ROOT), Ok("\\"));
        assert_eq!(ns.object_type(NodeId::ROOT), Ok(ObjectType::Directory));
        assert_eq!(ns.remove(NodeId::ROOT), Err(Error::PermissionDenied));
        assert_eq!(
            ns.create("\\", ObjectType::Event),
            Err(Error::AlreadyExists)
        );
        assert_eq!(ns.lookup("\\"), Ok(NodeId::ROOT));
    }

    #[test]
    fn nested_objects_are_created_under_their_directories() {
        let mut ns = ObjectNamespace::<8>::new();
        let base = ns
            .create("\\BaseNamedObjects", ObjectType::Directory)
            .unwrap();
        let event = ns
            .create("\\BaseNamedObjects\\MyEvent", ObjectType::Event)
            .unwrap();
        let other = ns.create("\\Other", ObjectType::Directory).unwrap();
        let shadow = ns.create("\\Other\\MyEvent", ObjectType::Event).unwrap();

        assert_ne!(event, shadow);
        assert_eq!(ns.lookup("\\BaseNamedObjects"), Ok(base));
        assert_eq!(ns.lookup("\\BaseNamedObjects\\MyEvent"), Ok(event));
        assert_eq!(ns.lookup("\\Other\\MyEvent"), Ok(shadow));
        assert_ne!(base, other);
        assert_eq!(ns.name(event), Ok("MyEvent"));
        assert_eq!(ns.object_type(event), Ok(ObjectType::Event));
        assert_eq!(ns.object_type(base), Ok(ObjectType::Directory));
    }

    #[test]
    fn lookup_is_case_insensitive_and_storage_preserves_case() {
        let mut ns = ObjectNamespace::<8>::new();
        ns.create("\\BaseNamedObjects", ObjectType::Directory)
            .unwrap();
        let event = ns
            .create("\\BaseNamedObjects\\MyEvent", ObjectType::Event)
            .unwrap();

        assert_eq!(ns.lookup("\\basenamedobjects\\MYEVENT"), Ok(event));
        assert_eq!(ns.lookup("\\BASENAMEDOBJECTS\\myevent"), Ok(event));
        assert_eq!(ns.name(event), Ok("MyEvent"));
    }

    #[test]
    fn missing_parent_is_not_found() {
        let mut ns = ObjectNamespace::<4>::new();
        assert_eq!(
            ns.create("\\Missing\\Event", ObjectType::Event),
            Err(Error::NotFound)
        );
        assert_eq!(ns.lookup("\\Missing"), Err(Error::NotFound));
        assert_eq!(ns.lookup("\\Missing\\Event"), Err(Error::NotFound));
        assert!(ns.create("\\Event", ObjectType::Event).is_ok());
    }

    #[test]
    fn parent_must_be_a_directory() {
        let mut ns = ObjectNamespace::<4>::new();
        ns.create("\\Event", ObjectType::Event).unwrap();
        assert_eq!(
            ns.create("\\Event\\Child", ObjectType::Event),
            Err(Error::InvalidState)
        );
        assert_eq!(ns.lookup("\\Event\\Child"), Err(Error::NotFound));
    }

    #[test]
    fn name_collisions_are_rejected_case_insensitively() {
        let mut ns = ObjectNamespace::<8>::new();
        let dir = ns.create("\\Dir", ObjectType::Directory).unwrap();
        let child = ns.create("\\Dir\\X", ObjectType::Event).unwrap();

        assert_eq!(
            ns.create("\\Dir", ObjectType::Directory),
            Err(Error::AlreadyExists)
        );
        assert_eq!(
            ns.create("\\dir\\x", ObjectType::Mutant),
            Err(Error::AlreadyExists)
        );
        assert_eq!(ns.lookup("\\DIR"), Ok(dir));
        assert_eq!(ns.lookup("\\dir\\X"), Ok(child));
        assert_eq!(ns.object_type(child), Ok(ObjectType::Event));
    }

    #[test]
    fn non_empty_directories_cannot_be_removed() {
        let mut ns = ObjectNamespace::<8>::new();
        let dir = ns.create("\\Dir", ObjectType::Directory).unwrap();
        let child = ns.create("\\Dir\\Event", ObjectType::Event).unwrap();

        assert_eq!(ns.remove(dir), Err(Error::InvalidState));
        assert_eq!(ns.lookup("\\Dir\\Event"), Ok(child));

        ns.remove(child).unwrap();
        ns.remove(dir).unwrap();
        assert_eq!(ns.lookup("\\Dir"), Err(Error::NotFound));
        assert_eq!(ns.remove(dir), Err(Error::InvalidHandle));
        assert_eq!(ns.name(dir), Err(Error::InvalidHandle));
    }

    #[test]
    fn invalid_paths_are_rejected_before_any_lookup() {
        let mut ns = ObjectNamespace::<4>::new();
        ns.create("\\Dir", ObjectType::Directory).unwrap();
        let mut long = [0u8; 80];
        let too_long = path_with_component(&mut long, MAX_NAME_LENGTH + 1);
        let mut max = [0u8; 80];
        let max_length = path_with_component(&mut max, MAX_NAME_LENGTH);
        let invalid = [
            "",
            "Dir",
            "Dir\\Event",
            "\\\\Dir",
            "\\Dir\\",
            "\\Dir\\\\Event",
            "\\Dir\\\0",
            "\\\0",
            "\\\u{c4}rger",
            too_long,
        ];
        for path in invalid {
            assert_eq!(ns.lookup(path), Err(Error::InvalidName), "lookup {path:?}");
            assert_eq!(
                ns.create(path, ObjectType::Event),
                Err(Error::InvalidName),
                "create {path:?}"
            );
        }

        // Exactly MAX_NAME_LENGTH bytes is accepted.
        let event = ns.create(max_length, ObjectType::Event).unwrap();
        assert_eq!(ns.lookup(max_length), Ok(event));
    }

    #[test]
    fn depth_is_bounded() {
        const DEEP: &str = "\\d\\d\\d\\d\\d\\d\\d\\d\\d\\d\\d\\d\\d\\d\\d\\d";
        const TOO_DEEP: &str = "\\d\\d\\d\\d\\d\\d\\d\\d\\d\\d\\d\\d\\d\\d\\d\\d\\d";
        let mut ns = ObjectNamespace::<32>::new();
        for depth in 1..=MAX_DEPTH {
            ns.create(&DEEP[..depth * 2], ObjectType::Directory)
                .unwrap();
        }
        assert!(ns.lookup(DEEP).is_ok());
        assert_eq!(
            ns.create(TOO_DEEP, ObjectType::Event),
            Err(Error::InvalidName)
        );
        assert_eq!(ns.lookup(TOO_DEEP), Err(Error::InvalidName));
    }

    #[test]
    fn capacity_is_exhausted_and_failed_creates_do_not_consume_slots() {
        let mut ns = ObjectNamespace::<3>::new();
        let a = ns.create("\\A", ObjectType::Event).unwrap();
        let b = ns.create("\\B", ObjectType::Event).unwrap();
        assert_ne!(a, b);
        assert_eq!(ns.create("\\C", ObjectType::Event), Err(Error::TableFull));
        assert_eq!(
            ns.create("\\A", ObjectType::Event),
            Err(Error::AlreadyExists)
        );
        assert_eq!(ns.lookup("\\C"), Err(Error::NotFound));
        assert_eq!(ns.lookup("\\A"), Ok(a));
        assert_eq!(ns.lookup("\\B"), Ok(b));
    }

    #[test]
    fn removed_slots_are_reused() {
        let mut ns = ObjectNamespace::<2>::new();
        let first = ns.create("\\First", ObjectType::Event).unwrap();
        assert_eq!(
            ns.create("\\Second", ObjectType::Event),
            Err(Error::TableFull)
        );

        ns.remove(first).unwrap();
        assert_eq!(ns.lookup("\\First"), Err(Error::NotFound));
        let second = ns.create("\\Second", ObjectType::Mutant).unwrap();
        assert_eq!(second.index, first.index);
        assert_ne!(second, first);
        assert_eq!(ns.lookup("\\Second"), Ok(second));
        assert_eq!(ns.name(second), Ok("Second"));
        assert_eq!(ns.object_type(second), Ok(ObjectType::Mutant));
    }

    #[test]
    fn stale_id_is_rejected_after_slot_is_reused() {
        let mut ns = ObjectNamespace::<2>::new();
        let first = ns.create("\\First", ObjectType::Event).unwrap();
        ns.remove(first).unwrap();
        let second = ns.create("\\Second", ObjectType::Mutant).unwrap();
        assert_eq!(second.index, first.index);

        assert_eq!(ns.name(first), Err(Error::InvalidHandle));
        assert_eq!(ns.object_type(first), Err(Error::InvalidHandle));
        assert_eq!(ns.remove(first), Err(Error::InvalidHandle));

        // The rejected remove must leave the object now occupying the slot alone.
        assert_eq!(ns.lookup("\\Second"), Ok(second));
        assert_eq!(ns.name(second), Ok("Second"));
        assert_eq!(ns.object_type(second), Ok(ObjectType::Mutant));
        ns.remove(second).unwrap();
        assert_eq!(ns.lookup("\\Second"), Err(Error::NotFound));
    }

    #[test]
    fn ids_are_rejected_while_their_slot_is_vacant_or_foreign() {
        let mut ns = ObjectNamespace::<4>::new();
        let event = ns.create("\\Event", ObjectType::Event).unwrap();
        ns.remove(event).unwrap();

        assert_eq!(ns.name(event), Err(Error::InvalidHandle));
        assert_eq!(ns.object_type(event), Err(Error::InvalidHandle));
        assert_eq!(ns.remove(event), Err(Error::InvalidHandle));

        let beyond = NodeId {
            index: 99,
            generation: 0,
        };
        assert_eq!(ns.name(beyond), Err(Error::InvalidHandle));
        assert_eq!(ns.object_type(beyond), Err(Error::InvalidHandle));
        assert_eq!(ns.remove(beyond), Err(Error::InvalidHandle));
    }

    #[test]
    fn root_stays_valid_through_churn() {
        let mut ns = ObjectNamespace::<4>::new();
        let dir = ns.create("\\Dir", ObjectType::Directory).unwrap();
        for _ in 0..100 {
            let event = ns.create("\\Dir\\Event", ObjectType::Event).unwrap();
            ns.remove(event).unwrap();
            let other = ns.create("\\Other", ObjectType::Mutant).unwrap();
            ns.remove(other).unwrap();
        }
        ns.remove(dir).unwrap();

        assert_eq!(ns.lookup("\\"), Ok(NodeId::ROOT));
        assert_eq!(ns.name(NodeId::ROOT), Ok("\\"));
        assert_eq!(ns.object_type(NodeId::ROOT), Ok(ObjectType::Directory));
        assert_eq!(ns.remove(NodeId::ROOT), Err(Error::PermissionDenied));
        assert_eq!(ns.lookup("\\"), Ok(NodeId::ROOT));
        assert!(ns.create("\\Late", ObjectType::Event).is_ok());
    }

    #[test]
    fn exhausted_generation_retires_the_slot() {
        let mut ns = ObjectNamespace::<3>::new();
        // Start the slot one generation short of overflow. Reaching the
        // maximum takes 2^32 cycles, so the test sets the counter directly.
        ns.nodes[1].generation = u32::MAX - 1;

        let before = ns.create("\\A", ObjectType::Event).unwrap();
        assert_eq!(
            before,
            NodeId {
                index: 1,
                generation: u32::MAX - 1,
            }
        );
        ns.remove(before).unwrap();

        // The final generation is still issued once.
        let last = ns.create("\\A", ObjectType::Event).unwrap();
        assert_eq!(
            last,
            NodeId {
                index: 1,
                generation: u32::MAX,
            }
        );
        ns.remove(last).unwrap();

        // The slot cannot advance, so it is retired rather than wrapped to 0,
        // which would make the old identifiers match again.
        assert_eq!(ns.lookup("\\A"), Err(Error::NotFound));
        assert_eq!(ns.name(before), Err(Error::InvalidHandle));
        assert_eq!(ns.name(last), Err(Error::InvalidHandle));
        assert_eq!(ns.remove(before), Err(Error::InvalidHandle));
        assert_eq!(ns.remove(last), Err(Error::InvalidHandle));

        // A retired slot is never handed out again: the other slot is used,
        // and then the table is full.
        let b = ns.create("\\B", ObjectType::Event).unwrap();
        assert_eq!(b.index, 2);
        assert_eq!(ns.create("\\C", ObjectType::Event), Err(Error::TableFull));
        assert_eq!(ns.lookup("\\B"), Ok(b));
    }

    #[test]
    fn zero_capacity_namespace_resolves_nothing() {
        let mut ns = ObjectNamespace::<0>::new();
        assert_eq!(ns.lookup("\\"), Err(Error::NotFound));
        assert_eq!(ns.create("\\A", ObjectType::Event), Err(Error::NotFound));
        assert_eq!(ns.remove(NodeId::ROOT), Err(Error::PermissionDenied));
    }
}
