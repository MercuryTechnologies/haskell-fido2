{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ViewPatterns #-}

module Crypto.Fido2.Operations.Attestation.AndroidSafetyNet
  ( format,
    Format (..),
    DecodingError (..),
    Statement (..),
    VerificationError (..),
  )
where

import Codec.CBOR.Term (Term (TBytes, TString))
import qualified Codec.CBOR.Term as CBOR
import Control.Monad.Except (runExcept)
import qualified Crypto.Fido2.Model as M
import Crypto.Hash (Digest)
import Crypto.Hash.Algorithms (SHA256)
import qualified Crypto.JOSE as JOSE
import qualified Crypto.JOSE.Error as JOSE
import qualified Crypto.JWT as JOSE
import Data.Bifunctor (Bifunctor (first))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LB
import Data.HashMap.Lazy (HashMap, (!?))
import qualified Data.Text as Text
import GHC.Exception (Exception)

data Format = Format

instance Show Format where
  show = Text.unpack . M.asfIdentifier

-- | [(spec)](https://developer.android.com/training/safetynet/attestation.html#compat-check-response)
data Response = Response
  { timestampMs :: Integer,
    nonce :: BS.ByteString,
    apkPackageName :: String,
    apkCertificateDigestSha256 :: Digest SHA256,
    ctsProfileMatch :: Bool,
    basicIntegrity :: Bool,
    evaluationType :: String
  }
  deriving (Eq, Show)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-android-safetynet-attestation)
data Statement = Statement
  { ver :: Text.Text,
    response :: Response
  }
  deriving (Eq, Show)

data DecodingError
  = -- | The provided CBOR encoded data was malformed. Either because a field
    -- was missing, or because the field contained the wrong type of data
    DecodingErrorUnexpectedCBORStructure (HashMap Text.Text CBOR.Term)
  | JWSError JOSE.Error
  deriving (Show, Exception)

data VerificationError
  = TEMP
  deriving (Show, Exception)

instance M.AttestationStatementFormat Format where
  type AttStmt Format = Statement
  asfIdentifier _ = "android-safetynet"

  type AttStmtDecodingError Format = DecodingError
  asfDecode _ xs =
    case (xs !? "ver", xs !? "response") of
      (Just (TString ver), Just (TBytes response)) -> do
        jwt :: JOSE.SignedJWT <- first JWSError $ runExcept $ JOSE.decodeCompact (LB.fromStrict response)
        error (show jwt)
      _ -> Left (DecodingErrorUnexpectedCBORStructure xs)
  asfEncode _ _ = CBOR.TMap []

  type AttStmtVerificationError Format = VerificationError
  asfVerify _ _ _ _ = Right M.AttestationTypeNone

format :: M.SomeAttestationStatementFormat
format = M.SomeAttestationStatementFormat Format
