{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeApplications #-}
-- traceMLockedForeignPtr is deprecated
{-# OPTIONS_GHC -Wno-deprecations #-}

{- FOURMOLU_DISABLE -}
module Main (main) where

import           Data.Proxy (Proxy (..))
import           Foreign.Storable (Storable (poke))
import           Control.Monad (void, when)
import           GHC.Fingerprint (Fingerprint (..))
import           System.Environment (getArgs)

#ifdef MIN_VERSION_unix
import           System.Posix.Process (getProcessID)
#endif

import qualified Data.ByteString as SB

import           Cardano.Crypto.Libsodium
import           Cardano.Crypto.Libsodium.MLockedBytes (traceMLSB)
import           Cardano.Crypto.Hash (SHA256, Blake2b_256, digest)

main :: IO ()
main = do
#ifdef MIN_VERSION_unix
    pid <- getProcessID

    putStrLn $ "If you run this test with 'pause' argument"
    putStrLn $ "you may look at /proc/" ++ show pid ++ "/maps"
    putStrLn $ "                /proc/" ++ show pid ++ "/smaps"
#endif

    sodiumInit

    args <- getArgs

    sodiumInit
    example args mlockedAllocForeignPtr

    -- example SHA256 hash
    do
      let input = SB.pack [0..255]
      hash <- digestMLockedBS (Proxy @SHA256) input
      traceMLSB hash
      print (digest (Proxy @SHA256) input)

    -- example Blake2b_256 hash
    do
      let input = SB.pack [0..255]
      hash <- digestMLockedBS (Proxy @Blake2b_256) input
      traceMLSB hash
      print (digest (Proxy @Blake2b_256) input)

example
    :: [String]
    -> IO (MLockedForeignPtr Fingerprint)
    -> IO ()
example args alloc = do
    -- create foreign ptr to mlocked memory
    fptr <- alloc
    withMLockedForeignPtr fptr $ \ptr -> poke ptr (Fingerprint 0xdead 0xc0de)

    when ("pause" `elem` args) $ do
        putStrLn "Allocated..."
        void getLine

    -- we shouldn't do this, but rather do computation inside
    -- withForeignPtr on provided Ptr a
    traceMLockedForeignPtr fptr

    -- smoke test that hashing works
    hash <- withMLockedForeignPtr fptr $ \ptr ->
        digestMLockedStorable (Proxy @SHA256) ptr
    traceMLSB hash

    -- force finalizers
    finalizeMLockedForeignPtr fptr

    when ("pause" `elem` args) $ do
        putStrLn "Finalized..."
        void getLine

    when ("use-after-free" `elem` args) $ do
        -- in this demo we can try to print it again.
        -- this should deterministically cause segmentation fault
        traceMLockedForeignPtr fptr
