{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ViewPatterns #-}

module Crypto.Fido2.Operations.Attestation.TPM
  ( format,
    Format (..),
    DecodingError (..),
    Statement (..),
    VerificationError (..),
  )
where

import qualified Codec.CBOR.Term as CBOR
import Control.Exception (Exception)
import Control.Monad (forM, unless, when)
import qualified Crypto.Fido2.Model as M
import Crypto.Fido2.PublicKey (COSEAlgorithmIdentifier, fromAlg, toAlg, toCOSEAlgorithmIdentifier)
import qualified Crypto.Fido2.PublicKey as PublicKey
import Data.ASN1.BinaryEncoding (DER (DER))
import Data.ASN1.Encoding (ASN1Decoding (decodeASN1))
import Data.ASN1.Error (ASN1Error)
import qualified Data.ASN1.OID as OID
import Data.ASN1.Prim (ASN1 (OctetString))
import Data.Bifunctor (first)
import Data.ByteArray (convert)
import qualified Data.ByteString as BS
import Data.ByteString.Lazy (fromStrict)
import Data.HashMap.Strict (HashMap, (!?))
import Data.List (find)
import Data.List.NonEmpty (NonEmpty ((:|)), toList)
import qualified Data.List.NonEmpty as NE
import Data.Maybe (isJust)
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.X509 as X509
import qualified Data.X509.Validation as X509

data Format = Format

instance Show Format where
  show = Text.unpack . M.asfIdentifier

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-tpm-attestation)
data Statement = Statement
  { alg :: COSEAlgorithmIdentifier,
    x5c :: Maybe M.NonEmptyCertificateChain,
    sig :: BS.ByteString,
    certInfo :: BS.ByteString,
    pubArea :: BS.ByteString
  }
  deriving (Eq, Show)

data DecodingError
  = -- | The provided CBOR encoded data was malformed. Either because a field
    -- was missing, or because the field contained the wrong type of data
    DecodingErrorUnexpectedCBORStructure (HashMap Text CBOR.Term)
  deriving (Show, Exception)

data VerificationError
  = TODOError
  deriving (Show, Exception)

instance M.AttestationStatementFormat Format where
  type AttStmt Format = Statement

  asfIdentifier _ = "tpm"

  type AttStmtDecodingError Format = DecodingError

  asfDecode _ xs =
    case (xs !? "alg", xs !? "sig", xs !? "x5c") of
      (Just (CBOR.TInt algId), Just (CBOR.TBytes sig), x5cValue) -> do
        undefined
      _ -> Left $ DecodingErrorUnexpectedCBORStructure xs

  asfEncode _ Statement {..} =
    undefined

  type AttStmtVerificationError Format = VerificationError

  asfVerify
    _
    Statement {..}
    M.AuthenticatorData {..}
    clientDataHash = do
      undefined

format :: M.SomeAttestationStatementFormat
format = M.SomeAttestationStatementFormat Format
