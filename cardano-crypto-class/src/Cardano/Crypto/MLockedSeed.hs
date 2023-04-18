{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
module Cardano.Crypto.MLockedSeed
where

import Cardano.Crypto.MonadMLock
  ( MLockedSizedBytes
  , MonadMLock (..)
  , mlsbCopy
  , mlsbNew
  , mlsbNewZero
  , mlsbFinalize
  , mlsbUseAsCPtr
  , mlsbUseAsSizedPtr
  , MEq (..)
  )
import Cardano.Foreign (SizedPtr)
import GHC.TypeNats (KnownNat)
import Control.DeepSeq (NFData)
import NoThunks.Class (NoThunks)
import Foreign.Ptr (Ptr)
import Data.Word (Word8)
import Control.Monad.Class.MonadST (MonadST)

-- | A seed of size @n@, stored in mlocked memory. This is required to prevent
-- the seed from leaking to disk via swapping and reclaiming or scanning memory
-- after its content has been moved.
newtype MLockedSeed n =
  MLockedSeed { mlockedSeedMLSB :: MLockedSizedBytes n }
  deriving (NFData, NoThunks)

deriving via (MLockedSizedBytes n)
  instance (MonadMLock m, MonadST m, KnownNat n) => MEq m (MLockedSeed n)

withMLockedSeedAsMLSB :: Functor m
                  => (MLockedSizedBytes n -> m (MLockedSizedBytes n))
                  -> MLockedSeed n
                  -> m (MLockedSeed n)
withMLockedSeedAsMLSB action =
  fmap MLockedSeed . action . mlockedSeedMLSB

mlockedSeedCopy :: (KnownNat n, MonadMLock m) => MLockedSeed n -> m (MLockedSeed n)
mlockedSeedCopy =
  withMLockedSeedAsMLSB mlsbCopy

mlockedSeedNew :: (KnownNat n, MonadMLock m) => m (MLockedSeed n)
mlockedSeedNew =
  MLockedSeed <$> mlsbNew

mlockedSeedNewZero :: (KnownNat n, MonadMLock m) => m (MLockedSeed n)
mlockedSeedNewZero =
  MLockedSeed <$> mlsbNewZero

mlockedSeedFinalize :: (MonadMLock m) => MLockedSeed n -> m ()
mlockedSeedFinalize = mlsbFinalize . mlockedSeedMLSB

mlockedSeedUseAsCPtr :: (MonadMLock m) => MLockedSeed n -> (Ptr Word8 -> m b) -> m b
mlockedSeedUseAsCPtr seed = mlsbUseAsCPtr (mlockedSeedMLSB seed)

mlockedSeedUseAsSizedPtr :: (MonadMLock m) => MLockedSeed n -> (SizedPtr n -> m b) -> m b
mlockedSeedUseAsSizedPtr seed = mlsbUseAsSizedPtr (mlockedSeedMLSB seed)
