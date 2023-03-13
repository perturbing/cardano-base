{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE RoleAnnotations #-}
{-# LANGUAGE TypeApplications #-}
module Cardano.Crypto.Libsodium.Hash (
    SodiumHashAlgorithm (..),
    digestMLockedStorable,
    digestMLockedBS,
    expandHash,
) where

import Data.Proxy (Proxy (..))
import Foreign.C.Types (CSize)
import Foreign.Ptr (castPtr, plusPtr)
import Foreign.Storable (Storable (poke))
import Data.Word (Word8)
import GHC.TypeLits

import Cardano.Crypto.Hash (HashAlgorithm(SizeHash))
import Cardano.Crypto.Libsodium.Hash.Class
import Cardano.Crypto.Libsodium.MLockedBytes.Internal
import Cardano.Crypto.MonadMLock.Class
import Cardano.Crypto.MonadMLock.Alloc
import Control.Monad.Class.MonadST (MonadST (..))
import Control.Monad.Class.MonadThrow (MonadThrow)
import Control.Monad.ST.Unsafe (unsafeIOToST)

-------------------------------------------------------------------------------
-- Hash expansion
-------------------------------------------------------------------------------

expandHash
    :: forall h m proxy.
       (SodiumHashAlgorithm m h, MonadMLock m, MonadST m, MonadThrow m)
    => proxy h
    -> MLockedSizedBytes m (SizeHash h)
    -> m (MLockedSizedBytes m (SizeHash h), MLockedSizedBytes m (SizeHash h))
expandHash h (MLSB sfptr) = do
    withMLockedForeignPtr sfptr $ \ptr -> do
        l <- mlockedAlloca size1 $ \ptr' -> do
              withLiftST $ \liftST -> liftST . unsafeIOToST $ do
                poke ptr' (1 :: Word8)
                copyMem (castPtr (plusPtr ptr' 1)) ptr size
              naclDigestPtr h ptr' (fromIntegral size1)

        r <- mlockedAlloca size1 $ \ptr' -> do
              withLiftST $ \liftST -> liftST . unsafeIOToST $ do
                poke ptr' (2 :: Word8)
                copyMem (castPtr (plusPtr ptr' 1)) ptr size
              naclDigestPtr h ptr' (fromIntegral size1)

        return (l, r)
  where
    size1 :: CSize
    size1 = size + 1

    size :: CSize
    size = fromInteger $ natVal (Proxy @(SizeHash h))

