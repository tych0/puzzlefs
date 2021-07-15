use std::cmp::min;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use nix::errno::Errno;
use walkdir::WalkDir;

use format::{
    BlobRef, BlobRefKind, DirEnt, DirList, FileChunk, FileChunkList, Ino, Inode, InodeAdditional, InodeMode,
    Result, Rootfs,
};
use oci::media_types;
use oci::{Descriptor, Image};
use reader::PuzzleFS;

mod fastcdc_fs;
use fastcdc_fs::{ChunkWithData, FastCDCWrapper};

fn walker(rootfs: &Path) -> WalkDir {
    // breadth first search for sharing, don't cross filesystems just to be safe, order by file
    // name.
    WalkDir::new(rootfs)
        .contents_first(false)
        .follow_links(false)
        .same_file_system(true)
        .sort_by(|a, b| a.file_name().cmp(b.file_name()))
}

fn generate_inodes_and_chunks(rootfs: &Path, oci: &Image) -> Result<Vec<InodeInfo>> {
    // TODO: ideally we'd not keep this whole setup in memory; however, we have to know the number
    // of inodes we're going to write for this metadata block so we can correctly compute offsets
    // for things that come after the inode list. Maybe we should just use non-local blob refs for
    // metadata? or maybe we should do away with fixed length inode encoding all together?

    // host to puzzlefs inode mapping for hard link deteciton
    let mut host_to_pfs = HashMap::<u64, Ino>::new();

    // any previous files which were not included in a chunk
    let mut prev_files = Vec::<ModeInfo>::new();
    let mut inodes = Vec::<InodeInfo>::new();

    let mut fcdc = FastCDCWrapper::new();

    let cur_ino = 1;

    for entry in walker(rootfs) {
        let e = entry.map_err(io::Error::from)?;
        let md = e.metadata().map_err(io::Error::from)?;

        // now that we know the ino of this thing, let's put it in the parent directory (assuming
        // this is not "/" for our image, aka inode #1)
        if cur_ino != 1 {
            // is this a hard link? if so, just use the existing ino we have rendered. otherewise,
            // use a new one
            let the_ino = host_to_pfs.get(&md.ino()).copied().unwrap_or(cur_ino);
            let parent_path = e.path().parent().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("no parent for {}", e.path().display()),
                )
            })?;
            let parent = inodes
                .get_mut(&fs::symlink_metadata(parent_path)?.ino())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("no pfs inode for {}", e.path().display()),
                    )
                })?;
            parent.add_entry(e.path(), the_ino)?;

            // if it was a hard link, we don't need to actually render it again
            if host_to_pfs.get(&md.ino()).is_some() {
                continue;
            }
        }

        host_to_pfs.insert(md.ino(), cur_ino);

        let additional = InodeAdditional::new(e.path(), &md)?;
        let mode =
            if md.is_dir() {
                ModeInfo::Dir { dir_list: DirList { entries: Vec::<DirEnt>::new()}};
            } else if md.is_file() {
                let mut f = fs::File::open(e.path())?;
                io::copy(&mut f, &mut fcdc)?;
                let mut written_chunks = write_chunks_to_oci(oci, &mut fcdc)?;

                let mut chunks = Vec::<FileChunk>::new();
                let file = ModeInfo::File { chunk_list: FileChunkList { chunks }};
                if written_chunks.is_empty() {
                    // this file wasn't big enough to cause a chunk to be generated, add it to the list
                    // of files pending for this chunk
                    prev_files.push(file);
                } else {
                    let fixed_chunk =
                        merge_chunks_and_prev_files(&mut written_chunks, &mut files, &mut prev_files)?;
                    chunks.push(fixed_chunk);
                    chunks.append(&mut written_chunks);
                }

                file
            } else {
                ModeInfo::Other
            };
        let inode = InodeInfo { ino: cur_ino, addiitonal, md, mode };
        inodes.push(inode);

        cur_ino += 1;
    }

    // all inodes done, we need to finish up the cdc chunking
    fcdc.finish();
    let mut written_chunks = write_chunks_to_oci(oci, &mut fcdc)?;

    // if we have chunks, we should have files too
    assert!(written_chunks.is_empty() || !prev_files.is_empty());
    assert!(!written_chunks.is_empty() || prev_files.is_empty());

    if !written_chunks.is_empty() {
        // merge everything leftover with all previous files. we expect an error here, since the in
        // put shoudl be exactly consumed and the final take_first_chunk() call should fail. TODO:
        // rearrange this to be less ugly.
        merge_chunks_and_prev_files(&mut written_chunks, &mut files, &mut prev_files).unwrap_err();

        // we should have consumed all the chunks.
        assert!(written_chunks.is_empty());
    }
    inodes.sort_by(|a, b| a.ino.cmp(&b.ino));
    Ok(inodes)
}

// a struct to hold an inode's information before it can be rendered into a format::Inode (e.g. the
// dir/chunk list offset is unknown because we haven't accumulated all the dir entries yet)
struct InodeInfo {
    ino: u64,
    additional: Option<InodeAdditional>,
    md: fs::Metadata,
    mode: ModeInfo,
}

impl InodeInfo {
    fn render(&self, inode_buf: &mut Vec<u8>, total_inode_size: u64, other_buf: &mut Vec<u8>) -> Result<()> {
        let additional_ref = d
            .additional
            .as_ref()
            .map::<Result<BlobRef>, _>(|add| {
                let br = BlobRef::local(total_inode_size + other_buf.len());
                serde_cbor::to_writer(&mut other_buf, &add)?;
                Ok(br)
            })
            .transpose()?;
        let mode = mode.render(&self.md, total_inode_size + other_buf.len(), other_buf)?;
        Inode::new_inode(self.ino, &self.md, mode, additional_ref)
    }
}

enum ModeInfo {
    Dir { dir_list: DirList },
    File { chunk_list: FileChunkList },
    Other,
}

impl ModeInfo {
    fn render(&self, md: &fs::Metadata, offset: u64, mut w: dyn io::Writer) -> Result<InodeMode> {
        let mode = match self {
            ModeInfo::Dir { dir_list } => {
                serde_cbor::to_writer(&mut w, dir_list)?;
                InodeMode::Dir { offset }
            },
            ModeInfo::File { chunk_list } => {
                serde_cbor::to_writer(&mut w, chunk_list)?;
                InodeMode::Reg { offset }
            },
            ModeInfo::Other => {
                if md.file_type().is_fifo() {
                    InodeMode::Fifo
                } else if md.file_type().is_char_device() {
                    let major = stat::major(md.rdev());
                    let minor = stat::minor(md.rdev());
                    InodeMode::Chr { major, minor }
                } else if md.file_type().is_block_device() {
                    let major = stat::major(md.rdev());
                    let minor = stat::minor(md.rdev());
                    InodeMode::Blk { major, minor }
                } else if md.file_type().is_symlink() {
                    InodeMode::Lnk
                } else if md.file_type().is_socket() {
                    InodeMode::Sock
                } else {
                    // "should never" happen
                    panic!("invalid other type: {:?}", md);
                }
            }
        };
        Ok(mode)
    }

    fn add_entry(&mut self, p: &Path, ino: Ino) -> Result<()> {
        if let ModeInfo::Dir { mut dir_list } = self {
            let name = p.file_name().ok_or_else(|| {
                io::Error::new(io::ErrorKind::Other, format!("no path for {}", p.display()))
            })?;
            self.dir_list.entries.push(DirEnt {
                name: name.to_os_string(),
                ino,
            });
            Ok(())
        } else {
            Err(WireFormatError::from_errno(Errno::ENOTDIR))
        }
    }

    fn add_chunk(&mut self, chunk: FileChunk) -> Result<()> {
        if let ModeInfo::File { mut chunk_list } = self {
            chunk_list.push(chunk);
            Ok(())
        } else {
            Err(WireFormatError::from_errno(Errno::EISDIR))
        }
    }
}

struct Dir {
    ino: u64,
    dir_list: DirList,
    md: fs::Metadata,
    additional: Option<InodeAdditional>,
}

// similar to the above, but holding file metadata
struct File {
    ino: u64,
    chunk_list: FileChunkList,
    md: fs::Metadata,
    additional: Option<InodeAdditional>,
}

struct Other {
    ino: u64,
    md: fs::Metadata,
    additional: Option<InodeAdditional>,
}

fn write_chunks_to_oci(oci: &Image, fcdc: &mut FastCDCWrapper) -> Result<Vec<FileChunk>> {
    let mut pending_chunks = Vec::<ChunkWithData>::new();
    fcdc.get_pending_chunks(&mut pending_chunks);
    pending_chunks
        .iter_mut()
        .map(|c| {
            let desc = oci.put_blob::<_, compression::Noop, media_types::Chunk>(&*c.data)?;
            Ok(FileChunk {
                blob: BlobRef {
                    kind: BlobRefKind::Other {
                        digest: desc.digest.underlying(),
                    },
                    offset: 0,
                },
                len: desc.size,
            })
        })
        .collect::<Result<Vec<FileChunk>>>()
}

fn take_first_chunk<FileChunk>(v: &mut Vec<FileChunk>) -> io::Result<FileChunk> {
    if !v.is_empty() {
        Ok(v.remove(0))
    } else {
        Err(io::Error::new(io::ErrorKind::Other, "missing blob"))
    }
}

fn merge_chunks_and_prev_files(
    chunks: &mut Vec<FileChunk>,
    files: &mut Vec<File>,
    prev_files: &mut Vec<File>,
) -> io::Result<FileChunk> {
    let mut chunk_used = 0;
    let mut chunk = take_first_chunk(chunks)?;

    for mut file in prev_files.drain(..) {
        let mut file_used: u64 = Iterator::sum(file.chunk_list.chunks.iter().map(|c| c.len));
        while file_used < file.md.len() {
            if chunk_used == chunk.len {
                chunk_used = 0;
                chunk = take_first_chunk(chunks)?;
            }

            let room = min(file.md.len() - file_used, chunk.len - chunk_used);
            let blob = BlobRef {
                offset: chunk_used,
                kind: chunk.blob.kind,
            };
            file.chunk_list.chunks.push(FileChunk { blob, len: room });
            chunk_used += room;
            file_used += room;
        }
        files.push(file);
    }

    if chunk_used == chunk.len {
        take_first_chunk(chunks)
    } else {
        // fix up the first chunk to have the right offset for this file
        Ok(FileChunk {
            blob: BlobRef {
                kind: chunk.blob.kind,
                offset: chunk_used,
            },
            len: chunk.len - chunk_used,
        })
    }
}

fn inode_encoded_size(num_inodes: usize) -> usize {
    format::cbor_size_of_list_header(num_inodes) + num_inodes * format::INODE_WIRE_SIZE
}

pub fn build_initial_rootfs(rootfs: &Path, oci: &Image) -> Result<Descriptor> {
    let inode_infos = generate_inodes_and_chunks(rootfs, oci)?;

    // total inode serailized size
    let inodes_serial_size = inode_encoded_size(inode_infos.len());

    let inode_buf = Vec::<u8>::with_capacity(inodes_serial_size);
    let other_buf = Vec::<u8>::new();

    let inodes = inode_infos.drain(..).map(|i| {
        i.render()
    }).collect::<Result<Vec<Inode>>>()?;

    // render dirs
    pfs_inodes.extend(
        dirs.values_mut()
            .collect::<Vec<_>>()
            .drain(..)
            .map(|d| {
                let dir_list_offset = inodes_serial_size + dir_buf.len();
                serde_cbor::to_writer(&mut dir_buf, &d.dir_list)?;
                Ok(Inode::new_dir(
                    d.ino,
                    &d.md,
                    dir_list_offset as u64,
                    additional_ref,
                )?)
            })
            .collect::<Result<Vec<Inode>>>()?,
    );

    let mut files_buf = Vec::<u8>::new();

    // render files
    pfs_inodes.extend(
        files
            .drain(..)
            .map(|f| {
                let chunk_offset = inodes_serial_size + dir_buf.len() + files_buf.len();
                serde_cbor::to_writer(&mut files_buf, &f.chunk_list)?;
                let additional_ref = f
                    .additional
                    .as_ref()
                    .map::<Result<BlobRef>, _>(|add| {
                        let offset = inodes_serial_size + dir_buf.len() + files_buf.len();
                        serde_cbor::to_writer(&mut files_buf, &add)?;
                        Ok(BlobRef {
                            offset: offset as u64,
                            kind: BlobRefKind::Local,
                        })
                    })
                    .transpose()?;
                Ok(Inode::new_file(
                    f.ino,
                    &f.md,
                    chunk_offset as u64,
                    additional_ref,
                )?)
            })
            .collect::<Result<Vec<Inode>>>()?,
    );

    let mut others_buf = Vec::<u8>::new();

    pfs_inodes.extend(
        others
            .drain(..)
            .map(|o| {
                let additional_ref = o
                    .additional
                    .as_ref()
                    .map::<Result<BlobRef>, _>(|add| {
                        let offset =
                            inodes_serial_size + dir_buf.len() + files_buf.len() + others_buf.len();
                        serde_cbor::to_writer(&mut others_buf, &add)?;
                        Ok(BlobRef {
                            offset: offset as u64,
                            kind: BlobRefKind::Local,
                        })
                    })
                    .transpose()?;
                Ok(Inode::new_other(o.ino, &o.md, additional_ref)?)
            })
            .collect::<Result<Vec<Inode>>>()?,
    );


    let mut md_buf = Vec::<u8>::with_capacity(
        inodes_serial_size + dir_buf.len() + files_buf.len() + others_buf.len(),
    );
    serde_cbor::to_writer(&mut md_buf, &pfs_inodes)?;

    assert_eq!(md_buf.len(), inodes_serial_size);

    md_buf.append(&mut dir_buf);
    md_buf.append(&mut files_buf);
    md_buf.append(&mut others_buf);

    let desc = oci.put_blob::<_, compression::Noop, media_types::Inodes>(md_buf.as_slice())?;
    let metadatas = [BlobRef {
        offset: 0,
        kind: BlobRefKind::Other {
            digest: desc.digest.underlying(),
        },
    }]
    .to_vec();

    let mut rootfs_buf = Vec::new();
    serde_cbor::to_writer(&mut rootfs_buf, &Rootfs { metadatas })?;
    oci.put_blob::<_, compression::Noop, media_types::Rootfs>(rootfs_buf.as_slice())
}

// add_delta_to_image generates a filesystem delta based on a full rootfs and an overlay workdir
// and adds it to the specified tag.
pub fn add_delta_to_image(full_rootfs: &Path, delta: &Path, oci: &Image, tag: &String) -> Result<Descriptor> {
    // Algorithm for adding a delta:
    //     1. generate a complete FCDC chunking of the new rootfs
    //     2. during this, keep track of what is present, what has been deleted
    //     3. for each thing that has been deleted, add a WHT inode in the filesystem.
    //     4. for each thing that is present
    //           if the chunk list is unchanged:
    //               continue
    //           render the new inode with only the delta
    let mut pfs = PuzzleFS::open(oci, tag)?;
    let mut cur_ino = pfs.max_inode()? + 1;

    for d in walker(delta) {
        let e = entry.map_err(io::Error::from)?;
        let md = e.metadata().map_err(io::Error::from)?;

        
    }
}

// TODO: figure out how to guard this with #[cfg(test)]
pub fn build_test_fs(image: &Image) -> Result<Descriptor> {
    build_initial_rootfs(Path::new("../builder/test"), image)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use std::convert::TryInto;

    use tempfile::tempdir;

    use format::{DirList, InodeMode};

    #[test]
    fn test_fs_generation() {
        // TODO: verify the hash value here since it's only one thing? problem is as we change the
        // encoding/add stuff to it, the hash will keep changing and we'll have to update the
        // test...
        //
        // but once all that's stabalized, we should verify the metadata hash too.
        let dir = tempdir().unwrap();
        let image = Image::new(dir.path()).unwrap();
        let rootfs_desc = build_test_fs(&image).unwrap();
        let rootfs = Rootfs::open(
            image
                .open_compressed_blob::<compression::Noop>(&rootfs_desc.digest)
                .unwrap(),
        )
        .unwrap();

        // there should be a blob that matches the hash of the test data, since it all gets input
        // as one chunk and there's only one file
        const FILE_DIGEST: &str =
            "d9e749d9367fc908876749d6502eb212fee88c9a94892fb07da5ef3ba8bc39ed";

        let md = fs::symlink_metadata(image.blob_path().join(FILE_DIGEST)).unwrap();
        assert!(md.is_file());

        let metadata_digest = rootfs.metadatas[0].try_into().unwrap();
        let mut blob = image
            .open_metadata_blob::<compression::Noop>(&metadata_digest)
            .unwrap();
        let inodes = blob.read_inodes().unwrap();

        // we can at least deserialize inodes and they look sane
        assert_eq!(inodes.len(), 2);

        assert_eq!(blob.find_inode(1).unwrap().unwrap(), inodes[0]);
        assert_eq!(blob.find_inode(2).unwrap().unwrap(), inodes[1]);

        assert_eq!(inodes[0].ino, 1);
        if let InodeMode::Dir { offset } = inodes[0].mode {
            let dir_list: DirList = blob.read_dir_list(offset).unwrap();
            assert_eq!(dir_list.entries.len(), 1);
            assert_eq!(dir_list.entries[0].ino, 2);
            assert_eq!(dir_list.entries[0].name, "SekienAkashita.jpg");
        } else {
            panic!("bad inode mode: {:?}", inodes[0].mode);
        }
        assert_eq!(inodes[0].uid, md.uid());
        assert_eq!(inodes[0].gid, md.gid());

        assert_eq!(inodes[1].ino, 2);
        assert_eq!(inodes[1].uid, md.uid());
        assert_eq!(inodes[1].gid, md.gid());
        if let InodeMode::Reg { offset } = inodes[1].mode {
            let chunks = blob.read_file_chunks(offset).unwrap();
            assert_eq!(chunks.len(), 1);
            assert_eq!(chunks[0].len, md.len());
        } else {
            panic!("bad inode mode: {:?}", inodes[1].mode);
        }
    }
}
