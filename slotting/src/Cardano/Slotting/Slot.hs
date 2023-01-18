{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DeriveTraversable #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Cardano.Slotting.Slot
  ( SlotNo (..),
    WithOrigin (..),
    at,
    origin,
    fromWithOrigin,
    withOrigin,
    withOriginToMaybe,
    withOriginFromMaybe,
    EpochNo (..),
    EpochSize (..),
  )
where

import Cardano.Binary (DecCBOR (..), EncCBOR (..))
import Codec.Serialise (Serialise (..))
import Control.DeepSeq (NFData (rnf))
import Data.Aeson (FromJSON, ToJSON)
import Data.Typeable (Typeable)
import Data.Word (Word64)
import GHC.Generics (Generic)
import Quiet (Quiet (..))
import NoThunks.Class (NoThunks)

-- | The 0-based index for the Ourboros time slot.
newtype SlotNo = SlotNo {unSlotNo :: Word64}
  deriving stock (Eq, Ord, Generic)
  deriving Show via Quiet SlotNo
  deriving newtype (Enum, Bounded, Num, NFData, Serialise, NoThunks, ToJSON, FromJSON)

instance EncCBOR SlotNo where
  encCBOR = encode

instance DecCBOR SlotNo where
  decCBOR = decode

{-------------------------------------------------------------------------------
  WithOrigin
-------------------------------------------------------------------------------}

data WithOrigin t = Origin | At !t
  deriving
    ( Eq,
      Ord,
      Show,
      Generic,
      Functor,
      Foldable,
      Traversable,
      Serialise,
      NoThunks
    )

instance (Serialise t, Typeable t) => EncCBOR (WithOrigin t) where
  encCBOR = encode

instance (Serialise t, Typeable t) => DecCBOR (WithOrigin t) where
  decCBOR = decode

instance Bounded t => Bounded (WithOrigin t) where
  minBound = Origin
  maxBound = At maxBound

instance NFData a => NFData (WithOrigin a) where
  rnf Origin = ()
  rnf (At t) = rnf t


at :: t -> WithOrigin t
at = At

origin :: WithOrigin t
origin = Origin

fromWithOrigin :: t -> WithOrigin t -> t
fromWithOrigin t Origin = t
fromWithOrigin _ (At t) = t

withOrigin :: b -> (t -> b) -> WithOrigin t -> b
withOrigin a _ Origin = a
withOrigin _ f (At t) = f t

withOriginToMaybe :: WithOrigin t -> Maybe t
withOriginToMaybe Origin = Nothing
withOriginToMaybe (At t) = Just t

withOriginFromMaybe :: Maybe t -> WithOrigin t
withOriginFromMaybe Nothing = Origin
withOriginFromMaybe (Just t) = At t

{-------------------------------------------------------------------------------
  Epochs
-------------------------------------------------------------------------------}

-- | An epoch, i.e. the number of the epoch.
newtype EpochNo = EpochNo {unEpochNo :: Word64}
  deriving stock (Eq, Ord, Generic)
  deriving Show via Quiet EpochNo
  deriving newtype (Enum, Num, Serialise, EncCBOR, DecCBOR, NoThunks, ToJSON, FromJSON, NFData)

newtype EpochSize = EpochSize {unEpochSize :: Word64}
  deriving stock (Eq, Ord, Generic)
  deriving Show via Quiet EpochSize
  deriving newtype (Enum, Num, Real, Integral, EncCBOR, DecCBOR, NoThunks, ToJSON, FromJSON, NFData)
