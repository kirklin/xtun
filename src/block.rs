//! The memory a reader reads frames into where every frame gets a stretch of its own: blocks of
//! one size, each shared by the reader and, once a frame in it was taken, by that frame. A block
//! that nothing holds any more goes back to the pool it came from, where the reader finds it
//! for a later frame.
//!
//! A pool starts out with its blocks side by side in one allocation. The system gives such an
//! allocation memory only where it is written to, and backs it with large pages where it has
//! them; the reader's blocks come from there for as long as frames give theirs back. Blocks
//! beyond those are allocated one by one.

use std::io;
use std::ptr::NonNull;
use std::sync::{Arc, Mutex, PoisonError};

/// Zeroed memory from the allocator, freed when it is dropped. Its bytes are reached only
/// through the pointer it hands out, never through a reference to all of it, so stretches of it
/// that are lent apart stay valid however its owner moves and whatever else of it is lent.
pub(crate) struct Memory(NonNull<[u8]>);

// SAFETY: the memory is an allocation of its own, which any thread may use and free.
unsafe impl Send for Memory {}
// SAFETY: as above; shared access reads only where the memory lies.
unsafe impl Sync for Memory {}

impl Memory {
    pub(crate) fn new(size: usize) -> Memory {
        let memory = Box::into_raw(vec![0u8; size].into_boxed_slice());
        Memory(NonNull::new(memory).expect("a box is never null"))
    }

    pub(crate) fn start(&self) -> NonNull<u8> {
        self.0.cast()
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
}

impl Drop for Memory {
    fn drop(&mut self) {
        // SAFETY: the memory came from a box, and nothing refers to it any more.
        drop(unsafe { Box::from_raw(self.0.as_ptr()) });
    }
}

/// The blocks of a pool that nothing holds.
#[derive(Default)]
struct Free {
    /// Where blocks of the pool's first allocation start.
    first: Vec<NonNull<u8>>,
    /// Blocks that were allocated one by one.
    more: Vec<Memory>,
}

// SAFETY: the pointers refer to the first allocation of the pool that holds the list, and are
// only handed on.
unsafe impl Send for Free {}

/// Blocks of one size.
pub struct Pool {
    size: usize,
    /// The allocation the pool started out with: its first blocks, side by side, for as long as
    /// the pool lives.
    _first: Memory,
    /// How many free blocks that were allocated one by one are kept; the rest is freed.
    keep: usize,
    free: Mutex<Free>,
}

impl Pool {
    /// A pool of blocks of `size` bytes, and its first `count` blocks, which lie side by side.
    /// The pool keeps up to `count` further blocks while they are free. Fails when the blocks
    /// together are larger than an allocation can be.
    pub fn new(size: usize, count: usize) -> io::Result<(Arc<Pool>, Vec<Arc<Block>>)> {
        let total = size.checked_mul(count).filter(|total| isize::try_from(*total).is_ok()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("{count} blocks of {size} bytes are larger than an allocation can be"))
        })?;
        let first = Memory::new(total);
        let start = first.start();
        let pool = Arc::new(Pool { size, _first: first, keep: count, free: Mutex::new(Free::default()) });
        // SAFETY: block `index` starts inside the allocation of `count` blocks.
        let blocks = (0..count).map(|index| Arc::new(Block { start: unsafe { start.add(index * size) }, more: None, pool: pool.clone() }));
        Ok((pool.clone(), blocks.collect()))
    }

    /// A block that nothing else holds: one of the first allocation if one is free, one that
    /// was allocated before, or a new one.
    pub fn block(self: &Arc<Pool>) -> Arc<Block> {
        let mut free = self.free.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(start) = free.first.pop() {
            return Arc::new(Block { start, more: None, pool: self.clone() });
        }
        let kept = free.more.pop();
        drop(free);
        let memory = kept.unwrap_or_else(|| Memory::new(self.size));
        Arc::new(Block { start: memory.start(), more: Some(memory), pool: self.clone() })
    }
}

/// One block. Whoever holds it alone may write to it; a reader that shares it with a frame
/// leaves its memory to the frame.
pub struct Block {
    start: NonNull<u8>,
    /// The block's own memory, for a block that is not part of its pool's first allocation.
    more: Option<Memory>,
    pool: Arc<Pool>,
}

// SAFETY: the memory is the pool's or the block's own; who may touch it is settled by who holds
// the block, on whatever thread.
unsafe impl Send for Block {}
// SAFETY: as above; shared access to the block itself reads only where its memory lies.
unsafe impl Sync for Block {}

impl Block {
    /// Where the block's memory starts.
    pub fn start(&self) -> NonNull<u8> {
        self.start
    }

    /// How many bytes the block has.
    pub fn len(&self) -> usize {
        self.pool.size
    }
}

impl Drop for Block {
    fn drop(&mut self) {
        let mut free = self.pool.free.lock().unwrap_or_else(PoisonError::into_inner);
        match self.more.take() {
            None => free.first.push(self.start),
            Some(memory) if free.more.len() < self.pool.keep => free.more.push(memory),
            Some(memory) => {
                drop(free);
                drop(memory);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn free(pool: &Pool) -> (usize, usize) {
        let free = pool.free.lock().unwrap();
        (free.first.len(), free.more.len())
    }

    #[test]
    fn the_first_blocks_lie_side_by_side_and_come_out_again_first() {
        let (pool, mut blocks) = Pool::new(4096, 2).unwrap();
        assert_eq!((blocks.len(), blocks[0].len()), (2, 4096));
        // SAFETY: both blocks start inside the pool's first allocation.
        assert_eq!(unsafe { blocks[0].start().add(4096) }, blocks[1].start());
        let (side, held) = (blocks[1].start(), blocks.remove(0));
        // Further blocks are allocations of their own.
        let (third, fourth, fifth) = (pool.block(), pool.block(), pool.block());
        assert!(third.more.is_some() && fourth.more.is_some() && fifth.more.is_some());
        drop(blocks);
        assert_eq!(free(&pool), (1, 0));
        let again = pool.block();
        assert_eq!(again.start(), side, "a block of the first allocation comes before any other");
        let shared = again.clone();
        drop(again);
        assert_eq!(free(&pool), (0, 0), "a block that is still held stays out");
        drop((shared, held));
        assert_eq!(free(&pool), (2, 0));
        drop((third, fourth, fifth));
        assert_eq!(free(&pool), (2, 2), "as many blocks of their own are kept as the pool started with");
        let out = [pool.block(), pool.block(), pool.block()];
        assert!(out[0].more.is_none() && out[1].more.is_none() && out[2].more.is_some());
        assert_eq!(free(&pool), (0, 1));
    }

    #[test]
    fn a_pool_without_first_blocks_hands_out_blocks() {
        let (pool, blocks) = Pool::new(64, 0).unwrap();
        assert!(blocks.is_empty());
        let block = pool.block();
        // SAFETY: the block is held alone.
        unsafe { block.start().write(7) };
        drop(block);
        assert_eq!(free(&pool), (0, 0), "a pool that keeps no block frees it");
    }

    #[test]
    fn a_pool_too_large_for_memory_is_refused() {
        let error = Pool::new(65_664, usize::MAX / 65_664 + 1).err().expect("the size overflows");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn a_block_outlives_what_made_it() {
        let (pool, mut blocks) = Pool::new(64, 4).unwrap();
        let block = blocks.remove(2);
        drop((pool, blocks));
        // SAFETY: the block is held alone, and keeps the pool's first allocation alive.
        unsafe { block.start().write(7) };
        drop(block);
    }
}
