use std::collections::VecDeque;
use std::path::PathBuf;

use super::error::FSResult;
use super::puzzlefs::{Inode, InodeMode, PuzzleFS};

/// A in iterator over a PuzzleFS filesystem. This iterates breadth first, since file content is
/// stored that way in a puzzlefs image so it'll be faster reading actual content if clients want
/// to do that.
pub struct WalkPuzzleFS<'a> {
    pfs: &'a mut PuzzleFS<'a>,
    q: VecDeque<DirEntry>,
}

impl<'a> WalkPuzzleFS<'a> {
    pub fn walk(pfs: &'a mut PuzzleFS<'a>) -> FSResult<WalkPuzzleFS<'a>> {
        let mut q = VecDeque::new();

        let inode = pfs.find_inode(1)?; // root inode number
        let de = DirEntry {
            path: PathBuf::from("/"),
            inode,
        };
        q.push_back(de);
        Ok(WalkPuzzleFS { pfs, q })
    }

    fn add_dir_entries(&mut self, dir: &DirEntry) -> FSResult<()> {
        if let InodeMode::Dir { ref entries } = dir.inode.mode {
            for (name, ino) in entries {
                let inode = self.pfs.find_inode(*ino)?;
                let path = dir.path.join(name);
                self.q.push_back(DirEntry { path, inode })
            }
        };

        Ok(())
    }
}

impl Iterator for WalkPuzzleFS<'_> {
    type Item = FSResult<DirEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        let de = self.q.pop_front()?;
        Some(self.add_dir_entries(&de).map(|_| de))
    }
}

pub struct DirEntry {
    pub path: PathBuf,
    pub inode: Inode,
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use builder::build_test_fs;
    use oci::Image;

    use super::*;

    #[test]
    fn test_walk() {
        // make ourselves a test image
        let oci_dir = tempdir().unwrap();
        let image = Image::new(oci_dir.path()).unwrap();
        let rootfs_desc = build_test_fs(&image).unwrap();
        image.add_tag("test".to_string(), rootfs_desc).unwrap();
        let mut pfs = PuzzleFS::open(&image, "test").unwrap();

        let mut walker = WalkPuzzleFS::walk(&mut pfs).unwrap();

        let root = walker.next().unwrap().unwrap();
        assert_eq!(root.path.to_string_lossy(), "/");
        assert_eq!(root.inode.inode.ino, 1);
        assert_eq!(root.inode.dir_entries().unwrap().len(), 1);

        let jpg_file = walker.next().unwrap().unwrap();
        assert_eq!(jpg_file.path.to_string_lossy(), "/SekienAkashita.jpg");
        assert_eq!(jpg_file.inode.inode.ino, 2);
        assert_eq!(jpg_file.inode.file_len().unwrap(), 109466);
    }
}
