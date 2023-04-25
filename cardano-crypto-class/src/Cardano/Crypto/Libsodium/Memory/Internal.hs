{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE CPP #-}
{-# OPTIONS_GHC -fprof-auto #-}
module Cardano.Crypto.Libsodium.Memory.Internal (
  -- * High-level memory management
  MLockedForeignPtr (..),
  withMLockedForeignPtr,
  finalizeMLockedForeignPtr,
  traceMLockedForeignPtr,
  mlockedMalloc,

  -- * Helper
  unsafeIOToMonadST
) where

import Control.DeepSeq (NFData (..), rwhnf)
import Control.Exception (mask_)
import Control.Monad (when)
import Data.Coerce (coerce)
import Data.Proxy (Proxy (..))
import Foreign.C.Error (errnoToIOError, getErrno)
import Foreign.C.Types (CSize (..))
import Foreign.Ptr (Ptr, nullPtr)
import Foreign.ForeignPtr (ForeignPtr, finalizeForeignPtr, touchForeignPtr)
import Foreign.ForeignPtr.Unsafe (unsafeForeignPtrToPtr)
import Foreign.Concurrent (newForeignPtr)
import Foreign.Storable (Storable (peek))
import Foreign.Marshal.Utils (fillBytes)
import GHC.TypeLits (KnownNat, natVal)
import GHC.IO.Exception (ioException)
import NoThunks.Class (NoThunks, OnlyCheckWhnfNamed (..))
import System.IO.Unsafe (unsafePerformIO)
import Control.Monad.Class.MonadST
import Control.Monad.ST.Unsafe (unsafeIOToST)
import Debug.Trace (traceShowM)

import Cardano.Crypto.Libsodium.C
import Cardano.Memory.Pool (initPool, grabNextBlock, Pool)

-- | Foreign pointer to securely allocated memory.
newtype MLockedForeignPtr a = SFP { _unwrapMLockedForeignPtr :: ForeignPtr a }
  deriving NoThunks via OnlyCheckWhnfNamed "MLockedForeignPtr" (MLockedForeignPtr a)

instance NFData (MLockedForeignPtr a) where
  rnf = rwhnf . _unwrapMLockedForeignPtr

withMLockedForeignPtr :: MonadST m => MLockedForeignPtr a -> (Ptr a -> m b) -> m b
withMLockedForeignPtr (SFP fptr) f = do
  r <- f (unsafeForeignPtrToPtr fptr)
  r <$ unsafeIOToMonadST (touchForeignPtr fptr)

finalizeMLockedForeignPtr :: MonadST m => MLockedForeignPtr a -> m ()
finalizeMLockedForeignPtr (SFP fptr) = withLiftST $ \lift ->
  (lift . unsafeIOToST) (finalizeForeignPtr fptr)

traceMLockedForeignPtr :: (Storable a, Show a, MonadST m) => MLockedForeignPtr a -> m ()
traceMLockedForeignPtr fptr = withMLockedForeignPtr fptr $ \ptr -> do
    a <- unsafeIOToMonadST (peek ptr)
    traceShowM a

{-# DEPRECATED traceMLockedForeignPtr "Don't leave traceMLockedForeignPtr in production" #-}

unsafeIOToMonadST :: MonadST m => IO a -> m a
unsafeIOToMonadST action = withLiftST ($ unsafeIOToST action)

makeMLockedPool :: forall n. KnownNat n => IO (Pool n)
makeMLockedPool = do
  initPool
    (max 1 . fromIntegral $ 4096 `div` natVal (Proxy @n) `div` 64)
    (\size -> mask_ $ do
      ptr <- sodiumMalloc (fromIntegral size)
      newForeignPtr ptr (sodiumFree ptr (fromIntegral size))
    )
    (\ptr -> do
      eraseMem (Proxy @n) ptr
    )

eraseMem :: forall n a. KnownNat n => Proxy n -> Ptr a -> IO ()
eraseMem proxy ptr = fillBytes ptr 0xff (fromIntegral $ natVal proxy)

mlockedPool32 :: Pool 32
mlockedPool32 = unsafePerformIO makeMLockedPool
{-# NOINLINE mlockedPool32 #-}

mlockedPool64 :: Pool 64
mlockedPool64 = unsafePerformIO makeMLockedPool
{-# NOINLINE mlockedPool64 #-}

mlockedPool128 :: Pool 128
mlockedPool128 = unsafePerformIO makeMLockedPool
{-# NOINLINE mlockedPool128 #-}

mlockedPool256 :: Pool 256
mlockedPool256 = unsafePerformIO makeMLockedPool
{-# NOINLINE mlockedPool256 #-}

mlockedPool512 :: Pool 512
mlockedPool512 = unsafePerformIO makeMLockedPool
{-# NOINLINE mlockedPool512 #-}

mlockedMalloc :: MonadST m => CSize -> m (MLockedForeignPtr a)
mlockedMalloc size = withLiftST ($ unsafeIOToST (mlockedMallocIO size))

mlockedMallocIO :: CSize -> IO (MLockedForeignPtr a)
mlockedMallocIO size = SFP <$> do
  if
    | size <= 32 -> do
        coerce $ grabNextBlock mlockedPool32
    | size <= 64 -> do
        coerce $ grabNextBlock mlockedPool64
    | size <= 128 -> do
        coerce $ grabNextBlock mlockedPool128
    | size <= 256 -> do
        coerce $ grabNextBlock mlockedPool256
    | size <= 512 -> do
        coerce $ grabNextBlock mlockedPool512
    | otherwise -> do
        mask_ $ do
          ptr <- sodiumMalloc size
          newForeignPtr ptr $ do
            sodiumFree ptr size

sodiumMalloc :: CSize -> IO (Ptr a)
sodiumMalloc size = do
  ptr <- c_sodium_malloc size
  when (ptr == nullPtr) $ do
      errno <- getErrno
      ioException $ errnoToIOError "c_sodium_malloc" errno Nothing Nothing
  res <- c_sodium_mlock ptr size
  when (res /= 0) $ do
      errno <- getErrno
      ioException $ errnoToIOError "c_sodium_mlock" errno Nothing Nothing
  return ptr

sodiumFree :: Ptr a -> CSize -> IO ()
sodiumFree ptr size = do
  res <- c_sodium_munlock ptr size
  when (res /= 0) $ do
    errno <- getErrno
    ioException $ errnoToIOError "c_sodium_munlock" errno Nothing Nothing
  c_sodium_free ptr
