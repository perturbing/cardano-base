{-# LANGUAGE CPP #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE NumericUnderscores #-}

module Test.Crypto.DSIGN
  ( tests
  )
where

{- HLINT ignore "Use <$>" -}
{- HLINT ignore "Reduce duplication" -}

import Test.QuickCheck (
  (=/=),
  (===),
  (==>),
  Arbitrary(..),
  Gen,
  Property,
  forAllShow,
  forAllShrinkShow,
  generate,
  property,
  ioProperty,
  )
import Test.Tasty (TestTree, testGroup, adjustOption)
import Test.Tasty.QuickCheck (testProperty, QuickCheckTests)

import qualified Data.ByteString as BS
import qualified Cardano.Crypto.Libsodium as NaCl

import Text.Show.Pretty (ppShow)

#ifdef SECP256K1_ENABLED
import Control.Monad (replicateM)
import qualified GHC.Exts as GHC
#endif

import qualified Test.QuickCheck.Gen as Gen
import Data.Kind (Type)
import Data.Proxy (Proxy (..))

import Control.Exception (evaluate, bracket)

import Cardano.Crypto.DSIGN (
  MockDSIGN,
  Ed25519DSIGN,
  Ed25519DSIGNM,
  Ed448DSIGN,
#ifdef SECP256K1_ENABLED
  EcdsaSecp256k1DSIGN,
  SchnorrSecp256k1DSIGN,
  MessageHash,
  toMessageHash,
#endif
  DSIGNAlgorithm (
    VerKeyDSIGN,
    SignKeyDSIGN,
    SigDSIGN,
    ContextDSIGN,
    Signable,
    rawSerialiseVerKeyDSIGN,
    rawDeserialiseVerKeyDSIGN,
    rawSerialiseSignKeyDSIGN,
    rawDeserialiseSignKeyDSIGN,
    rawSerialiseSigDSIGN,
    rawDeserialiseSigDSIGN
    ),
  sizeVerKeyDSIGN,
  sizeSignKeyDSIGN,
  sizeSigDSIGN,
  encodeVerKeyDSIGN,
  decodeVerKeyDSIGN,
  encodeSignKeyDSIGN,
  decodeSignKeyDSIGN,
  encodeSigDSIGN,
  decodeSigDSIGN,
  signDSIGN,
  deriveVerKeyDSIGN,
  verifyDSIGN,
  genKeyDSIGN,
  seedSizeDSIGN,
  hashAndPack,

  DSIGNMAlgorithmBase (VerKeyDSIGNM,
                      SignKeyDSIGNM,
                      SigDSIGNM,
                      ContextDSIGNM,
                      SignableM,
                      SeedSizeDSIGNM,
                      rawSerialiseVerKeyDSIGNM,
                      rawDeserialiseVerKeyDSIGNM,
                      rawSerialiseSigDSIGNM,
                      rawDeserialiseSigDSIGNM),
  DSIGNMAlgorithm (
                  rawSerialiseSignKeyDSIGNM,
                  rawDeserialiseSignKeyDSIGNM),
  sizeVerKeyDSIGNM,
  sizeSignKeyDSIGNM,
  sizeSigDSIGNM,
  encodeVerKeyDSIGNM,
  decodeVerKeyDSIGNM,
  -- encodeSignKeyDSIGNM,
  -- decodeSignKeyDSIGNM,
  encodeSigDSIGNM,
  decodeSigDSIGNM,
  signDSIGNM,
  deriveVerKeyDSIGNM,
  verifyDSIGNM,
  genKeyDSIGNM,
  seedSizeDSIGNM,

  getSeedDSIGNM,
  forgetSignKeyDSIGNM
  )
import Cardano.Binary (FromCBOR, ToCBOR)
import Cardano.Crypto.PinnedSizedBytes (PinnedSizedBytes)
import Test.Crypto.Util (
  Message (messageBytes),
  prop_raw_serialise,
  prop_raw_deserialise,
  prop_size_serialise,
  prop_cbor_with,
  prop_cbor,
  prop_cbor_size,
  prop_cbor_direct_vs_class,
  prop_no_thunks,
  arbitrarySeedOfSize,
  arbitrarySeedBytesOfSize,
  genBadInputFor,
  shrinkBadInputFor,
  showBadInputFor,
  -- prop_no_thunks_IO_from,
  -- prop_no_thunks_IO_with,
  Lock, withLock
  )
import Test.Crypto.Instances (withMLSBFromPSB)
import Cardano.Crypto.SECP256K1.Constants (SECP256K1_ECDSA_MESSAGE_BYTES)
import GHC.TypeLits (natVal)
import Cardano.Crypto.Hash (SHA3_256, HashAlgorithm (SizeHash), Blake2b_256, SHA256, Keccak256)

mockSigGen :: Gen (SigDSIGN MockDSIGN)
mockSigGen = defaultSigGen

ed25519SigGen :: Gen (SigDSIGN Ed25519DSIGN)
ed25519SigGen = defaultSigGen

ed25519SigGenM :: Gen (IO (SigDSIGNM Ed25519DSIGNM))
ed25519SigGenM = defaultSigGenM

ed448SigGen :: Gen (SigDSIGN Ed448DSIGN)
ed448SigGen = defaultSigGen

#ifdef SECP256K1_ENABLED
ecdsaSigGen :: Gen (SigDSIGN EcdsaSecp256k1DSIGN)
ecdsaSigGen = do
  msg <- genEcdsaMsg
  signDSIGN () msg <$> defaultSignKeyGen

schnorrSigGen :: Gen (SigDSIGN SchnorrSecp256k1DSIGN)
schnorrSigGen = defaultSigGen

genEcdsaMsg :: Gen MessageHash
genEcdsaMsg =
  Gen.suchThatMap (GHC.fromListN 32 <$> replicateM 32 arbitrary)
                  toMessageHash
#endif

defaultVerKeyGen :: forall (a :: Type) .
  (DSIGNAlgorithm a) => Gen (VerKeyDSIGN a)
defaultVerKeyGen = deriveVerKeyDSIGN <$> defaultSignKeyGen @a

defaultSignKeyGen :: forall (a :: Type).
  (DSIGNAlgorithm a) => Gen (SignKeyDSIGN a)
defaultSignKeyGen =
  genKeyDSIGN <$> arbitrarySeedOfSize (seedSizeDSIGN (Proxy :: Proxy a))

defaultSigGen :: forall (a :: Type) .
  (DSIGNAlgorithm a, ContextDSIGN a ~ (), Signable a Message) =>
  Gen (SigDSIGN a)
defaultSigGen = do
  msg :: Message <- arbitrary
  signDSIGN () msg <$> defaultSignKeyGen

-- Used for adjusting no of quick check tests
-- By default up to 100 tests are performed which may not be enough to catch hidden bugs
defaultTestEnough :: QuickCheckTests -> QuickCheckTests
defaultTestEnough = max 10_000

{- HLINT ignore "Use <$>" -}
{- HLINT ignore "Reduce duplication" -}

defaultSignKeyGenM :: forall (a :: Type).
  (DSIGNMAlgorithm IO a) => Gen (IO (SignKeyDSIGNM a))
defaultSignKeyGenM = do
  rawSeed <- arbitrarySeedBytesOfSize (seedSizeDSIGNM (Proxy :: Proxy a))
  return $ do
    seed <- NaCl.mlsbFromByteString @(SeedSizeDSIGNM a) rawSeed
    genKeyDSIGNM seed

defaultSigGenM :: forall (a :: Type) .
  (DSIGNMAlgorithm IO a, ContextDSIGNM a ~ (), SignableM a Message) =>
  Gen (IO (SigDSIGNM a))
defaultSigGenM = do
  msg :: Message <- arbitrary
  mkSK <- defaultSignKeyGenM
  return $ do
    sk <- mkSK
    sig <- signDSIGNM () msg sk
    forgetSignKeyDSIGNM sk
    return sig

--
-- The list of all tests
--
tests :: Lock -> TestTree
tests lock =
  testGroup "Crypto.DSIGN"
    [ testDSIGNAlgorithm mockSigGen (arbitrary @Message) "MockDSIGN"
    , testDSIGNAlgorithm ed25519SigGen (arbitrary @Message) "Ed25519DSIGN"
    , testDSIGNAlgorithm ed448SigGen (arbitrary @Message) "Ed448DSIGN"
#ifdef SECP256K1_ENABLED
    , testDSIGNAlgorithm ecdsaSigGen genEcdsaMsg "EcdsaSecp256k1DSIGN"
    , testDSIGNAlgorithm schnorrSigGen (arbitrary @Message) "SchnorrSecp256k1DSIGN"
    -- Specific tests related only to ecdsa
    , testEcdsaInvalidMessageHash "EcdsaSecp256k1InvalidMessageHash"
    , testEcdsaWithHashAlgorithm (Proxy @SHA3_256) "EcdsaSecp256k1WithSHA3_256"
    , testEcdsaWithHashAlgorithm (Proxy @Blake2b_256) "EcdsaSecp256k1WithBlake2b_256"
    , testEcdsaWithHashAlgorithm (Proxy @SHA256) "EcdsaSecp256k1WithSHA256"
    , testEcdsaWithHashAlgorithm (Proxy @Keccak256) "EcdsaSecp256k1WithKeccak256"
#endif
    , testDSIGNMAlgorithm lock ed25519SigGenM ed25519SigGen (arbitrary @Message) "Ed25519DSIGNM"
    ]

testDSIGNAlgorithm :: forall (v :: Type) (a :: Type).
  (DSIGNAlgorithm v,
   Signable v a,
   ContextDSIGN v ~ (),
   Show a,
   Eq (SignKeyDSIGN v),
   Eq a,
   ToCBOR (VerKeyDSIGN v),
   FromCBOR (VerKeyDSIGN v),
   ToCBOR (SignKeyDSIGN v),
   FromCBOR (SignKeyDSIGN v),
   ToCBOR (SigDSIGN v),
   FromCBOR (SigDSIGN v)) =>
  Gen (SigDSIGN v) ->
  Gen a ->
  String ->
  TestTree
testDSIGNAlgorithm genSig genMsg name = adjustOption testEnough . testGroup name $ [
  testGroup "serialization" [
    testGroup "raw" [
      testProperty "VerKey serialization" .
        forAllShow (defaultVerKeyGen @v)
                   ppShow $
                   prop_raw_serialise rawSerialiseVerKeyDSIGN rawDeserialiseVerKeyDSIGN,
      testProperty "VerKey deserialization (wrong length)" .
        forAllShrinkShow (genBadInputFor . expectedVKLen $ expected)
                         (shrinkBadInputFor @(VerKeyDSIGN v))
                         showBadInputFor $
                         prop_raw_deserialise rawDeserialiseVerKeyDSIGN,
      testProperty "SignKey serialization" .
        forAllShow (defaultSignKeyGen @v)
                   ppShow $
                   prop_raw_serialise rawSerialiseSignKeyDSIGN rawDeserialiseSignKeyDSIGN,
      testProperty "SignKey deserialization (wrong length)" .
        forAllShrinkShow (genBadInputFor . expectedSKLen $ expected)
                         (shrinkBadInputFor @(SignKeyDSIGN v))
                         showBadInputFor $
                         prop_raw_deserialise rawDeserialiseSignKeyDSIGN,
      testProperty "Sig serialization" .
        forAllShow genSig
                   ppShow $
                   prop_raw_serialise rawSerialiseSigDSIGN rawDeserialiseSigDSIGN,
      testProperty "Sig deserialization (wrong length)" .
        forAllShrinkShow (genBadInputFor . expectedSigLen $ expected)
                         (shrinkBadInputFor @(SigDSIGN v))
                         showBadInputFor $
                         prop_raw_deserialise rawDeserialiseSigDSIGN
      ],
    testGroup "size" [
      testProperty "VerKey" .
        forAllShow (defaultVerKeyGen @v)
                   ppShow $
                   prop_size_serialise rawSerialiseVerKeyDSIGN (sizeVerKeyDSIGN (Proxy @v)),
      testProperty "SignKey" .
        forAllShow (defaultSignKeyGen @v)
                   ppShow $
                   prop_size_serialise rawSerialiseSignKeyDSIGN (sizeSignKeyDSIGN (Proxy @v)),
      testProperty "Sig" .
        forAllShow genSig
                   ppShow $
                   prop_size_serialise rawSerialiseSigDSIGN (sizeSigDSIGN (Proxy @v))
      ],
    testGroup "direct CBOR" [
      testProperty "VerKey" .
        forAllShow (defaultVerKeyGen @v)
                   ppShow $
                   prop_cbor_with encodeVerKeyDSIGN decodeVerKeyDSIGN,
      testProperty "SignKey" .
        forAllShow (defaultSignKeyGen @v)
                   ppShow $
                   prop_cbor_with encodeSignKeyDSIGN decodeSignKeyDSIGN,
      testProperty "Sig" .
        forAllShow genSig
                   ppShow $
                   prop_cbor_with encodeSigDSIGN decodeSigDSIGN
      ],
    testGroup "To/FromCBOR class" [
      testProperty "VerKey" . forAllShow (defaultVerKeyGen @v) ppShow $ prop_cbor,
      testProperty "SignKey" . forAllShow (defaultSignKeyGen @v) ppShow $ prop_cbor,
      testProperty "Sig" . forAllShow genSig ppShow $ prop_cbor
      ],
    testGroup "ToCBOR size" [
      testProperty "VerKey" . forAllShow (defaultVerKeyGen @v) ppShow $ prop_cbor_size,
      testProperty "SignKey" . forAllShow (defaultSignKeyGen @v) ppShow $ prop_cbor_size,
      testProperty "Sig" . forAllShow genSig ppShow $ prop_cbor_size
      ],
    testGroup "direct matches class" [
      testProperty "VerKey" .
        forAllShow (defaultVerKeyGen @v) ppShow $
        prop_cbor_direct_vs_class encodeVerKeyDSIGN,
      testProperty "SignKey" .
        forAllShow (defaultSignKeyGen @v) ppShow $
        prop_cbor_direct_vs_class encodeSignKeyDSIGN,
      testProperty "Sig" .
        forAllShow genSig ppShow $
        prop_cbor_direct_vs_class encodeSigDSIGN
      ]
    ],
    testGroup "verify" [
      testProperty "signing and verifying with matching keys" .
        forAllShow ((,) <$> genMsg <*> defaultSignKeyGen @v) ppShow $
        prop_dsign_verify,
      testProperty "verifying with wrong key" .
        forAllShow genWrongKey ppShow $
        prop_dsign_verify_wrong_key,
      testProperty "verifying wrong message" .
        forAllShow genWrongMsg ppShow $
        prop_dsign_verify_wrong_msg
    ],
    testGroup "NoThunks" [
      testProperty "VerKey" . forAllShow (defaultVerKeyGen @v) ppShow $ prop_no_thunks,
      testProperty "SignKey" . forAllShow (defaultSignKeyGen @v) ppShow $ prop_no_thunks,
      testProperty "Sig" . forAllShow genSig ppShow $ prop_no_thunks
    ]
  ]
  where
    expected :: ExpectedLengths v
    expected = defaultExpected
    genWrongKey :: Gen (a, SignKeyDSIGN v, SignKeyDSIGN v)
    genWrongKey = do
      sk1 <- defaultSignKeyGen
      sk2 <- Gen.suchThat defaultSignKeyGen (/= sk1)
      msg <- genMsg
      pure (msg, sk1, sk2)
    genWrongMsg :: Gen (a, a, SignKeyDSIGN v)
    genWrongMsg = do
      msg1 <- genMsg
      msg2 <- Gen.suchThat genMsg (/= msg1)
      sk <- defaultSignKeyGen
      pure (msg1, msg2, sk)
    testEnough :: QuickCheckTests -> QuickCheckTests
    testEnough = max 10_000

testDSIGNMAlgorithm
  :: forall v w a. ( DSIGNMAlgorithm IO v
                 , ToCBOR (VerKeyDSIGNM v)
                 , FromCBOR (VerKeyDSIGNM v)
                 -- DSIGNM cannot satisfy To/FromCBOR, because those
                 -- typeclasses assume that a non-monadic
                 -- encoding/decoding exists.  Hence, we only test direct
                 -- encoding/decoding for 'SignKeyDSIGNM'.
                 -- , ToCBOR (SignKeyDSIGNM v)
                 -- , FromCBOR (SignKeyDSIGNM v)
                 , Eq (SignKeyDSIGNM v)   -- no Eq for signing keys normally
                 , ToCBOR (SigDSIGNM v)
                 , FromCBOR (SigDSIGNM v)
                 , SignableM v a
                 , ContextDSIGNM v ~ ()
                 , Eq a
                 )
  => Lock
  -> Gen (IO (SigDSIGNM v))
  -> Gen (SigDSIGN w)
  -> Gen a
  -> String
  -> TestTree
testDSIGNMAlgorithm lock _ _ mkMsg n =
  testGroup n
    [ testGroup "serialisation"
      [ testGroup "raw"
        [ testProperty "VerKey" $ \seedPSB ->
            ioProperty . withLock lock . withMLSBFromPSB seedPSB $ \seed -> do
              vk :: VerKeyDSIGNM v <- withSK seed deriveVerKeyDSIGNM
              return $ (rawDeserialiseVerKeyDSIGNM . rawSerialiseVerKeyDSIGNM $ vk) === Just vk
        , testProperty "SignKey" $ \seedPSB ->
            ioProperty . withLock lock . withMLSBFromPSB seedPSB $ \seed -> do
              withSK seed $ \sk -> do
                serialized <- rawSerialiseSignKeyDSIGNM sk
                msk' <- rawDeserialiseSignKeyDSIGNM serialized
                equals <- evaluate (Just sk == msk')
                maybe (return ()) forgetSignKeyDSIGNM msk'
                return equals
        , testProperty "Sig" $ \seedPSB -> property $ do
            msg <- mkMsg
            return . ioProperty . withLock lock . withMLSBFromPSB seedPSB $ \seed -> do
              sig :: SigDSIGNM v <- withSK seed (signDSIGNM () msg)
              return $ (rawDeserialiseSigDSIGNM . rawSerialiseSigDSIGNM $ sig) === Just sig
        ]
      , testGroup "size"
        [ testProperty "VerKey" $ \seedPSB -> do
            ioProperty . withLock lock . withMLSBFromPSB seedPSB $ \seed -> do
              vk :: VerKeyDSIGNM v <- withSK seed deriveVerKeyDSIGNM
              return $ (fromIntegral . BS.length . rawSerialiseVerKeyDSIGNM $ vk) === (sizeVerKeyDSIGNM (Proxy @v))
        , testProperty "SignKey" $ \seedPSB -> do
            ioProperty . withLock lock . withMLSBFromPSB seedPSB $ \seed -> do
              serialized <- withSK seed rawSerialiseSignKeyDSIGNM
              equals <- evaluate ((fromIntegral . BS.length $ serialized) == (sizeSignKeyDSIGNM (Proxy @v)))
              return equals
        , testProperty "Sig" $ \seedPSB -> property $ do
            msg <- mkMsg
            return . ioProperty . withLock lock . withMLSBFromPSB seedPSB $ \seed -> do
              sig :: SigDSIGNM v <- withSK seed (signDSIGNM () msg)
              return $ (fromIntegral . BS.length . rawSerialiseSigDSIGNM $ sig) === (sizeSigDSIGNM (Proxy @v))
        ]

      , testGroup "direct CBOR"
        [ testProperty "VerKey" $ \seedPSB ->
            ioProperty . withLock lock . withMLSBFromPSB seedPSB $ \seed -> do
              vk :: VerKeyDSIGNM v <- withSK seed deriveVerKeyDSIGNM
              return $ prop_cbor_with encodeVerKeyDSIGNM decodeVerKeyDSIGNM vk
        -- No CBOR testing for SignKey: sign keys are stored in MLocked memory
        -- and require IO for access.
        , testProperty "Sig" $ \seedPSB -> property $ do
            msg <- mkMsg
            return . ioProperty . withLock lock . withMLSBFromPSB seedPSB $ \seed -> do
              sig :: SigDSIGNM v <- withSK seed (signDSIGNM () msg)
              return $ prop_cbor_with encodeSigDSIGNM decodeSigDSIGNM sig
        ]

      , testGroup "To/FromCBOR class"
        [ testProperty "VerKey"  $ \seedPSB ->
            ioProperty . withLock lock . withMLSBFromPSB seedPSB $ \seed -> do
              vk :: VerKeyDSIGNM v <- withSK seed deriveVerKeyDSIGNM
              return $ prop_cbor vk
        -- No To/FromCBOR for 'SignKeyDSIGNM', see above.
        , testProperty "Sig" $ \seedPSB -> property $ do
            msg <- mkMsg
            return . ioProperty . withLock lock . withMLSBFromPSB seedPSB $ \seed -> do
              sig :: SigDSIGNM v <- withSK seed (signDSIGNM () msg)
              return $ prop_cbor sig
        ]

      , testGroup "ToCBOR size"
        [ testProperty "VerKey"  $ \seedPSB ->
            ioProperty . withLock lock . withMLSBFromPSB seedPSB $ \seed -> do
              vk :: VerKeyDSIGNM v <- withSK seed deriveVerKeyDSIGNM
              return $ prop_cbor_size vk
        -- No To/FromCBOR for 'SignKeyDSIGNM', see above.
        , testProperty "Sig" $ \seedPSB -> property $ do
            msg <- mkMsg
            return . ioProperty . withLock lock . withMLSBFromPSB seedPSB $ \seed -> do
              sig :: SigDSIGNM v <- withSK seed (signDSIGNM () msg)
              return $ prop_cbor_size sig
        ]

      , testGroup "direct matches class"
        [ testProperty "VerKey" $ \seedPSB ->
            ioProperty . withLock lock . withMLSBFromPSB seedPSB $ \seed -> do
              vk :: VerKeyDSIGNM v <- withSK seed deriveVerKeyDSIGNM
              return $ prop_cbor_direct_vs_class encodeVerKeyDSIGNM vk
        -- No CBOR testing for SignKey: sign keys are stored in MLocked memory
        -- and require IO for access.
        , testProperty "Sig" $ \seedPSB -> property $ do
            msg <- mkMsg
            return . ioProperty . withLock lock . withMLSBFromPSB seedPSB $ \seed -> do
              sig :: SigDSIGNM v <- withSK seed (signDSIGNM () msg)
              return $ prop_cbor_direct_vs_class encodeSigDSIGNM sig
        ]
      ]

    , testGroup "verify"
      [ testProperty "verify positive" $ prop_dsignm_verify_pos @v @a lock (Proxy @v) mkMsg
      , testProperty "verify negative (wrong key)" $ prop_dsignm_verify_neg_key @v @a lock (Proxy @v) mkMsg
      , testProperty "verify negative (wrong message)" $ prop_dsignm_verify_neg_msg @v @a lock (Proxy @v) mkMsg
      ]

    , testGroup "seed extraction"
      [ testProperty "extracted seed equals original seed" $ prop_dsignm_seed_roundtrip lock (Proxy @v)
      ]

    , testGroup "forgetting"
      [ testProperty "key overwritten after forget" $ prop_key_overwritten_after_forget lock (Proxy @v)
      ]

    -- , testGroup "NoThunks"
    --   [ testProperty "VerKey"  $ prop_no_thunks_IO_from @(VerKeyDSIGNM v) lock genVerKeyDSIGNM
    --   , testProperty "SignKey" $ prop_no_thunks_IO_from @(SignKeyDSIGNM v) lock genKeyDSIGNM
    --   , testProperty "Sig"     $ prop_no_thunks_IO_with @(SigDSIGNM v) lock mkSigM
    --   ]
    ]
  where
    withSK :: forall b. NaCl.MLockedSizedBytes (SeedSizeDSIGNM v) -> (SignKeyDSIGNM v -> IO b) -> IO b
    withSK seed action =
      bracket
        (genKeyDSIGNM seed)
        forgetSignKeyDSIGNM
        action

prop_key_overwritten_after_forget
  :: forall v.
     (DSIGNMAlgorithm IO v
     )
  => Lock
  -> Proxy v
  -> PinnedSizedBytes (SeedSizeDSIGNM v)
  -> Property
prop_key_overwritten_after_forget lock p seedPSB =
  ioProperty . withLock lock . withMLSBFromPSB seedPSB $ \seed -> do
    sk <- genKeyDSIGNM seed
    NaCl.mlsbFinalize seed

    seedBefore <- getSeedDSIGNM p sk
    bsBefore <- evaluate $! BS.copy (NaCl.mlsbToByteString seedBefore)
    NaCl.mlsbFinalize seedBefore

    forgetSignKeyDSIGNM sk

    seedAfter <- getSeedDSIGNM p sk
    bsAfter <- evaluate $! BS.copy (NaCl.mlsbToByteString seedAfter)
    NaCl.mlsbFinalize seedAfter

    return (bsBefore =/= bsAfter)

prop_dsignm_seed_roundtrip
  :: forall v.
     ( DSIGNMAlgorithm IO v
     )
  => Lock
  -> Proxy v
  -> PinnedSizedBytes (SeedSizeDSIGNM v)
  -> Property
prop_dsignm_seed_roundtrip lock p seedPSB = ioProperty . withLock lock . withMLSBFromPSB seedPSB $ \seed -> do
  sk <- genKeyDSIGNM seed
  seed' <- getSeedDSIGNM p sk
  bs <- evaluate $! BS.copy (NaCl.mlsbToByteString seed)
  bs' <- evaluate $! BS.copy (NaCl.mlsbToByteString seed')
  forgetSignKeyDSIGNM sk
  NaCl.mlsbFinalize seed'
  return (bs === bs')

-- If we sign a message with the key, we can verify the signature with the
-- corresponding verification key.
prop_dsign_verify
  :: forall (v :: Type) (a :: Type) .
     ( DSIGNAlgorithm v
     , ContextDSIGN v ~ ()
     , Signable v a
     )
  => (a, SignKeyDSIGN v)
  -> Property
prop_dsign_verify (msg, sk) =
  let signed = signDSIGN () msg sk
      vk = deriveVerKeyDSIGN sk
    in verifyDSIGN () vk msg signed === Right ()

-- If we sign a message with one key, and try to verify with another, then
-- verification fails.
prop_dsign_verify_wrong_key
  :: forall (v :: Type) (a :: Type) .
     ( DSIGNAlgorithm v
     , ContextDSIGN v ~ ()
     , Signable v a
     )
  => (a, SignKeyDSIGN v, SignKeyDSIGN v)
  -> Property
prop_dsign_verify_wrong_key (msg, sk, sk') =
  let signed = signDSIGN () msg sk
      vk' = deriveVerKeyDSIGN sk'
    in verifyDSIGN () vk' msg signed =/= Right ()

prop_dsignm_verify_pos
  :: forall v a. (DSIGNMAlgorithm IO v, ContextDSIGNM v ~ (), SignableM v a)
  => Lock
  -> Proxy v
  -> Gen a
  -> PinnedSizedBytes (SeedSizeDSIGNM v)
  -> Property
prop_dsignm_verify_pos lock _ mkMsg seedPSB = ioProperty . withLock lock . withMLSBFromPSB seedPSB $ \seed -> do
  a <- generate $ mkMsg
  (sk :: SignKeyDSIGNM v) <- genKeyDSIGNM seed
  sig <- signDSIGNM () a sk
  vk <- deriveVerKeyDSIGNM sk
  forgetSignKeyDSIGNM sk
  return $ verifyDSIGNM () vk a sig === Right ()

-- | If we sign a message @a@ with one signing key, if we try to verify the
-- signature (and message @a@) using a verification key corresponding to a
-- different signing key, then the verification fails.
--
prop_dsignm_verify_neg_key
  :: forall v a. (DSIGNMAlgorithm IO v, ContextDSIGNM v ~ (), SignableM v a)
  => Lock
  -> Proxy v
  -> Gen a
  -> PinnedSizedBytes (SeedSizeDSIGNM v)
  -> PinnedSizedBytes (SeedSizeDSIGNM v)
  -> Property
prop_dsignm_verify_neg_key lock _ mkMsg seed seed' = ioProperty . withLock lock $ do
  a <- generate $ mkMsg
  (sk :: SignKeyDSIGNM v) <- withMLSBFromPSB seed $ genKeyDSIGNM
  (sk' :: SignKeyDSIGNM v) <- withMLSBFromPSB seed' $ genKeyDSIGNM
  sig <- signDSIGNM () a sk
  vk' <- deriveVerKeyDSIGNM sk'
  forgetSignKeyDSIGNM sk
  forgetSignKeyDSIGNM sk'
  return $
    seed /= seed' ==> verifyDSIGNM () vk' a sig =/= Right ()

-- If we sign a message with a key, but then try to verify with a different
-- message, then verification fails.
prop_dsign_verify_wrong_msg
  :: forall (v :: Type) (a :: Type) .
  (DSIGNAlgorithm v, Signable v a, ContextDSIGN v ~ ())
  => (a, a, SignKeyDSIGN v)
  -> Property
prop_dsign_verify_wrong_msg (msg, msg', sk) =
  let signed = signDSIGN () msg sk
      vk = deriveVerKeyDSIGN sk
    in verifyDSIGN () vk msg' signed =/= Right ()

data ExpectedLengths (v :: Type) =
  ExpectedLengths {
    expectedVKLen :: Int,
    expectedSKLen :: Int,
    expectedSigLen :: Int
    }

defaultExpected ::
  forall (v :: Type) .
  (DSIGNAlgorithm v) =>
  ExpectedLengths v
defaultExpected = ExpectedLengths {
  expectedVKLen = fromIntegral . sizeVerKeyDSIGN $ Proxy @v,
  expectedSKLen = fromIntegral . sizeSignKeyDSIGN $ Proxy @v,
  expectedSigLen = fromIntegral . sizeSigDSIGN $ Proxy @v
  }

testEcdsaInvalidMessageHash :: String -> TestTree
testEcdsaInvalidMessageHash name = adjustOption defaultTestEnough . testGroup name $ [
    testProperty "MessageHash deserialization (wrong length)" .
      forAllShrinkShow (genBadInputFor expectedMHLen)
                       (shrinkBadInputFor @MessageHash)
                       showBadInputFor $ prop_raw_deserialise toMessageHash
  ]
  where
    expectedMHLen :: Int
    expectedMHLen = fromIntegral $ natVal $ Proxy @SECP256K1_ECDSA_MESSAGE_BYTES

testEcdsaWithHashAlgorithm ::
  forall (h :: Type).
  (HashAlgorithm h, SizeHash h ~ SECP256K1_ECDSA_MESSAGE_BYTES) =>
  Proxy h -> String -> TestTree
testEcdsaWithHashAlgorithm _ name = adjustOption defaultTestEnough . testGroup name $ [
    testProperty "Ecdsa sign and verify" .
    forAllShow ((,) <$> genMsg <*> defaultSignKeyGen @EcdsaSecp256k1DSIGN) ppShow $
      prop_dsign_verify
  ]
  where
    genMsg :: Gen MessageHash
    genMsg = hashAndPack (Proxy @h) . messageBytes <$> arbitrary

prop_dsignm_verify_neg_msg
  :: forall v a. (DSIGNMAlgorithm IO v, ContextDSIGNM v ~ (), SignableM v a, Eq a)
  => Lock
  -> Proxy v
  -> Gen a
  -> PinnedSizedBytes (SeedSizeDSIGNM v)
  -> Property
prop_dsignm_verify_neg_msg lock _ mkMsg seed = ioProperty . withLock lock $ do
  a <- generate $ mkMsg
  a' <- generate $ mkMsg
  (sk :: SignKeyDSIGNM v) <- withMLSBFromPSB seed $ genKeyDSIGNM
  sig <- signDSIGNM () a sk
  vk <- deriveVerKeyDSIGNM sk
  forgetSignKeyDSIGNM sk
  return $
    a /= a' ==> verifyDSIGNM () vk a' sig =/= Right ()
--
-- Libsodium
--

-- TODO: use these

-- prop_sodium_genKey
--     :: forall v w.
--        ( DSIGNMAlgorithm IO v
--        , DSIGNAlgorithm w
--        )
--     => Proxy v
--     -> Proxy w
--     -> MLockedSeed (SeedSizeDSIGNM v)
--     -> Property
-- prop_sodium_genKey _p _q seed = ioProperty $ do
--     sk <- genKeyDSIGNM seed :: IO (SignKeyDSIGNM v)
--     let sk' = genKeyDSIGN (mkSeedFromBytes $ NaCl.mlsbToByteString seed) :: SignKeyDSIGN w
--     actual <- rawSerialiseSignKeyDSIGNM sk
--     let expected = rawSerialiseSignKeyDSIGN sk'
--     return (actual === expected)
--
-- fromJustCS :: HasCallStack => Maybe a -> a
-- fromJustCS (Just x) = x
-- fromJustCS Nothing  = error "fromJustCS"
--
-- -- | Given the monadic and pure flavors of the same DSIGN algorithm, show that
-- -- they derive the same verkey
-- prop_sodium_deriveVerKey
--     :: forall v w
--      . (DSIGNMAlgorithm IO v, DSIGNAlgorithm w)
--     => Proxy v
--     -> Proxy w
--     -> SignKeyDSIGNM v
--     -> Property
-- prop_sodium_deriveVerKey p q sk = ioProperty $ do
--   Just sk' <- (rawDeserialiseSignKeyDSIGN <$> rawSerialiseSignKeyDSIGNM sk) :: IO (Maybe (SignKeyDSIGN w))
--   actual <- rawSerialiseVerKeyDSIGNM <$> deriveVerKeyDSIGNM sk
--   let expected = rawSerialiseVerKeyDSIGN $ deriveVerKeyDSIGN sk'
--   return (actual === expected)
--
-- prop_sodium_sign
--     :: forall v w.
--        ( DSIGNMAlgorithm IO v
--        , DSIGNAlgorithm w
--        , SignableM v ~ SignableRepresentation
--        , Signable w ~ SignableRepresentation
--        , ContextDSIGNM v ~ ()
--        , ContextDSIGN w ~ ()
--        )
--     => Proxy v
--     -> Proxy w
--     -> SignKeyDSIGNM v
--     -> [Word8]
--     -> Property
-- prop_sodium_sign p q sk bytes = ioProperty $ do
--   Just sk' <- rawDeserialiseSignKeyDSIGN <$> rawSerialiseSignKeyDSIGNM sk
--   actual <- rawSerialiseSigDSIGNM <$> (signDSIGNM () msg sk :: IO (SigDSIGNM v))
--   let expected = rawSerialiseSigDSIGN $ (signDSIGN () msg sk' :: SigDSIGN w)
--   return (actual === expected)
--   where
--     msg = BS.pack bytes
--
-- prop_sodium_verify
--     :: forall v w.
--        ( DSIGNMAlgorithm IO v
--        , DSIGNAlgorithm w
--        , SignableM v ~ SignableRepresentation
--        , Signable w ~ SignableRepresentation
--        , ContextDSIGNM v ~ ()
--        , ContextDSIGN w ~ ()
--        )
--     => Proxy v
--     -> Proxy w
--     -> SignKeyDSIGNM v
--     -> [Word8]
--     -> Property
-- prop_sodium_verify p q sk bytes = ioProperty $ do
--     Just sk' <- rawDeserialiseSignKeyDSIGN <$> rawSerialiseSignKeyDSIGNM sk
--     vk <- deriveVerKeyDSIGNM sk
--     let vk' = deriveVerKeyDSIGN sk'
--     sig <- signDSIGNM () msg sk
--     let sig' = signDSIGN () msg sk' :: SigDSIGN w
--
--     let actual = verifyDSIGNM () vk msg sig
--     let expected = verifyDSIGN () vk' msg sig'
--     return $ label (con expected) $ actual === expected
--   where
--     msg = BS.pack bytes
--     con :: Either a b -> String
--     con (Left _) = "Left"
--     con (Right _) = "Right"
--
-- prop_sodium_verify_neg
--     :: forall v w.
--        ( DSIGNMAlgorithm IO v
--        , DSIGNAlgorithm w
--        , SignableM v ~ SignableRepresentation
--        , Signable w ~ SignableRepresentation
--        , ContextDSIGNM v ~ ()
--        , ContextDSIGN w ~ ()
--        )
--     => Proxy v
--     -> Proxy w
--     -> SignKeyDSIGNM v
--     -> [Word8]
--     -> SigDSIGNM v
--     -> Property
-- prop_sodium_verify_neg p q sk bytes sig = ioProperty $ do
--     Just sk' <- rawDeserialiseSignKeyDSIGN <$> rawSerialiseSignKeyDSIGNM sk
--     vk <- deriveVerKeyDSIGNM sk
--     let vk' = deriveVerKeyDSIGN sk'
--     let Just sig' = rawDeserialiseSigDSIGN $ rawSerialiseSigDSIGNM sig :: Maybe (SigDSIGN w)
--     let actual = verifyDSIGNM () vk msg sig
--     let expected = verifyDSIGN () vk' msg sig'
--     return $ label (con expected) $ actual === expected
--   where
--     msg = BS.pack bytes
--     con :: Either a b -> String
--     con (Left _) = "Left"
--     con (Right _) = "Right"
