{-# LANGUAGE DataKinds #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE ViewPatterns #-}

module Main
  ( main,
  )
where

import Control.Concurrent.STM (TVar)
import qualified Control.Concurrent.STM as STM
import Control.Monad (unless, when)
import Control.Monad.IO.Class (liftIO)
import qualified Crypto.Fido2.Model as M
import qualified Crypto.Fido2.Model.JavaScript as JS
import Crypto.Fido2.Model.JavaScript.Decoding (decodeCreatedPublicKeyCredential, decodeRequestedPublicKeyCredential)
import Crypto.Fido2.Model.JavaScript.Encoding (encodePublicKeyCredentialCreationOptions, encodePublicKeyCredentialRequestOptions)
import Crypto.Fido2.Operations.Assertion (verifyAssertionResponse)
import Crypto.Fido2.Operations.Attestation (AttestationError, allSupportedFormats, verifyAttestationResponse)
import Crypto.Fido2.Operations.Common (CredentialEntry (CredentialEntry, ceCredentialId))
import Crypto.Fido2.PublicKey (COSEAlgorithmIdentifier (COSEAlgorithmIdentifierES256))
import Crypto.Hash (hash)
import Data.Aeson (FromJSON)
import qualified Data.ByteString.Base64.URL as Base64
import Data.List (find)
import Data.List.NonEmpty (NonEmpty ((:|)))
import Data.Map (Map)
import qualified Data.Map as Map
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import qualified Data.Text.IO as Text
import qualified Data.Text.Lazy as LText
import Data.Validation (Validation (Failure, Success))
import qualified Database
import GHC.Generics (Generic)
import qualified Network.HTTP.Types as HTTP
import Network.Wai.Middleware.Static (addBase, staticPolicy)
import Session (IsSession (initialSession), SessionId, casSession, getSessionScotty)
import System.Environment (getArgs)
import System.Random.Stateful (globalStdGen, uniformM)
import Web.Scotty (ScottyM)
import qualified Web.Scotty as Scotty

-- Session data that we store for each user.
--
--                         +----> Registering ---+
--                         |                     |
--      Unauthenticated ---+                     +---> Authenticated
--                         |                     |
--                         +---> Authenticating -+
--
--  Whether we consider Authenticated right after Registering is a design
--  choice. Should be safe to do? But let's double check that the spec
--  actually guarantees that you own the public key after registering.
data Session
  = Unauthenticated
  | Registering (M.PublicKeyCredentialOptions 'M.Create)
  | Authenticating M.UserHandle (M.PublicKeyCredentialOptions 'M.Get)
  | Authenticated M.UserHandle
  deriving (Eq, Show)

instance IsSession Session where
  initialSession = Unauthenticated

type Sessions = Map SessionId Session

isUnauthenticated :: Session -> Bool
isUnauthenticated session = case session of
  Unauthenticated -> True
  _ -> False

isAuthenticated :: Session -> Bool
isAuthenticated session = case session of
  Authenticated _ -> True
  _ -> False

data RegisterBeginReq = RegisterBeginReq
  { userName :: Text,
    displayName :: Text
  }
  deriving (Show, FromJSON)
  deriving stock (Generic)

app :: M.Origin -> M.RpIdHash -> Database.Connection -> TVar Sessions -> ScottyM ()
app origin rpIdHash db sessions = do
  Scotty.middleware (staticPolicy (addBase "dist"))
  Scotty.post "/register/begin" $ beginRegistration db sessions
  Scotty.post "/register/complete" $ completeRegistration origin rpIdHash db sessions
  Scotty.post "/login/begin" $ beginLogin db sessions
  Scotty.post "/login/complete" $ completeLogin origin rpIdHash db sessions
  Scotty.get "/requires-auth" $ do
    (_sessionId, session) <- getSessionScotty sessions
    unless (isAuthenticated session) (Scotty.raiseStatus HTTP.status401 "Please authenticate first")
    Scotty.json @Text $ "This should only be visible when authenticated"

mkCredentialDescriptor :: CredentialEntry -> M.PublicKeyCredentialDescriptor
mkCredentialDescriptor CredentialEntry {ceCredentialId} =
  M.PublicKeyCredentialDescriptor
    { M.pkcdTyp = M.PublicKeyCredentialTypePublicKey,
      M.pkcdId = ceCredentialId,
      M.pkcdTransports = Nothing
    }

data RegistrationResult
  = RegistrationSuccess
  | AlreadyRegistered
  | AttestationError AttestationError
  deriving (Show)

handleError :: Show e => Either e a -> Scotty.ActionM a
handleError (Left x) = Scotty.raiseStatus HTTP.status400 . LText.fromStrict . Text.pack . show $ x
handleError (Right x) = pure x

beginLogin :: Database.Connection -> TVar Sessions -> Scotty.ActionM ()
beginLogin db sessions = do
  (sessionId, session) <- getSessionScotty sessions
  userId' <- Scotty.jsonData @Text
  userId <- case Base64.decodeUnpadded (Text.encodeUtf8 userId') of
    Left err -> fail $ "Failed to base64url decode the user id " <> show userId' <> ": " <> err
    Right res -> pure $ M.UserHandle res
  credentials <- liftIO $
    Database.withTransaction db $ \tx -> do
      Database.getCredentialsByUserId tx userId
  when (null credentials) $ Scotty.raiseStatus HTTP.status404 "User not found"
  unless
    (isUnauthenticated session)
    (Scotty.raiseStatus HTTP.status400 "You need to be unauthenticated to begin login")
  challenge <- liftIO $ uniformM globalStdGen
  let options =
        M.PublicKeyCredentialRequestOptions
          { M.pkcogRpId = Nothing,
            M.pkcogTimeout = Nothing,
            M.pkcogChallenge = challenge,
            M.pkcogAllowCredentials = Just (map mkCredentialDescriptor credentials),
            M.pkcogUserVerification = Nothing,
            M.pkcogExtensions = Nothing
          }
  liftIO $ STM.atomically $ casSession sessions sessionId session (Authenticating userId options)
  Scotty.json $ encodePublicKeyCredentialRequestOptions options

completeLogin :: M.Origin -> M.RpIdHash -> Database.Connection -> TVar Sessions -> Scotty.ActionM ()
completeLogin origin rpIdHash db sessions = do
  (sessionId, session) <- getSessionScotty sessions
  case session of
    Authenticating userHandle options -> verifyLogin sessionId session userHandle options
    _ -> Scotty.raiseStatus HTTP.status400 "You need to be authenticating to complete login"
  where
    verifyLogin :: SessionId -> Session -> M.UserHandle -> M.PublicKeyCredentialOptions 'M.Get -> Scotty.ActionM ()
    verifyLogin sessionId session userHandle options = do
      credential <- Scotty.jsonData @JS.RequestedPublicKeyCredential

      cred <- case decodeRequestedPublicKeyCredential credential of
        Left err -> fail $ show err
        Right result -> pure result

      -- TODO: Query for the credential id directly
      entries <- liftIO $
        Database.withTransaction db $ \tx -> Database.getCredentialsByUserId tx userHandle
      entry <- case find ((== M.pkcIdentifier cred) . ceCredentialId) entries of
        Nothing -> fail "Credential not found"
        Just entry -> pure entry

      -- step 1 to 17
      -- We abort if we couldn't attest the credential
      -- FIXME
      _newSigCount <- case verifyAssertionResponse origin rpIdHash Nothing entry options cred of
        Failure (err :| _) -> fail $ show err
        Success result -> pure result
      -- FIXME: Set new signature count
      liftIO $
        STM.atomically $
          casSession sessions sessionId session (Authenticated userHandle)
      Scotty.json @Text "Welcome."

beginRegistration :: Database.Connection -> TVar Sessions -> Scotty.ActionM ()
beginRegistration db sessions = do
  (sessionId, session) <- getSessionScotty sessions
  -- NOTE: We currently do not support multiple credentials per user.
  case session of
    Unauthenticated -> generateRegistrationChallenge sessionId session
    _ -> Scotty.raiseStatus HTTP.status400 "You need to be unauthenticated to begin registration"
  where
    generateRegistrationChallenge :: SessionId -> Session -> Scotty.ActionM ()
    generateRegistrationChallenge sessionId session = do
      req@RegisterBeginReq {userName, displayName} <- Scotty.jsonData @RegisterBeginReq
      liftIO $ putStrLn $ "/register/begin, received " <> show req
      challenge <- liftIO $ uniformM globalStdGen
      userId <- liftIO $ uniformM globalStdGen
      let user =
            M.PublicKeyCredentialUserEntity
              { M.pkcueId = userId,
                M.pkcueDisplayName = M.UserAccountDisplayName displayName,
                M.pkcueName = M.UserAccountName userName
              }
      let options = defaultPkcco user challenge
      liftIO $ putStrLn $ "/register/begin, sending " <> show options
      Scotty.json $ encodePublicKeyCredentialCreationOptions options
      liftIO $
        Database.withTransaction db $ \tx -> do
          Database.addUser tx user
          STM.atomically $ casSession sessions sessionId session (Registering options)

completeRegistration :: M.Origin -> M.RpIdHash -> Database.Connection -> TVar Sessions -> Scotty.ActionM ()
completeRegistration origin rpIdHash db sessions = do
  (sessionId, session) <- getSessionScotty sessions
  case session of
    Registering options ->
      verifyRegistration sessionId options
    _ ->
      Scotty.raiseStatus
        HTTP.status400
        "You need to be registering to complete registration"
  where
    verifyRegistration :: SessionId -> M.PublicKeyCredentialOptions 'M.Create -> Scotty.ActionM ()
    verifyRegistration sessionId options = do
      let userHandle = M.pkcueId $ M.pkcocUser options
      credential <- Scotty.jsonData @JS.CreatedPublicKeyCredential
      cred <- case decodeCreatedPublicKeyCredential allSupportedFormats credential of
        Left err -> do
          liftIO $ putStrLn $ "/register/complete, failure " <> show err
          fail $ show err
        Right result -> do
          liftIO $ putStrLn $ "/register/complete, received " <> show result
          pure result
      -- step 1 to 17
      -- We abort if we couldn't attest the credential
      -- FIXME
      entry <- case verifyAttestationResponse origin rpIdHash options cred of
        Failure (err :| _) -> fail $ show err
        Success result -> pure result
      -- if the credential was succesfully attested, we will see if the
      -- credential doesn't exist yet, and if it doesn't, insert it.
      result <- liftIO $
        Database.withTransaction db $ \tx -> do
          -- If a credential with this id existed already, it must belong to the
          -- current user, otherwise it's an error. The spec allows removing the
          -- credential from the old user instead, but we don't do that.
          existingUserId <- Database.getUserByCredentialId tx (ceCredentialId entry)
          case existingUserId of
            Nothing -> do
              Database.addAttestedCredentialData tx entry
              pure $ Right ()
            Just existingUserId | userHandle == existingUserId -> pure $ Right ()
            Just _differentUserId -> pure $ Left AlreadyRegistered
      handleError result
      liftIO $ STM.atomically $ STM.modifyTVar sessions $ Map.insert sessionId (Authenticated userHandle)

defaultPkcco :: M.PublicKeyCredentialUserEntity -> M.Challenge -> M.PublicKeyCredentialOptions 'M.Create
defaultPkcco userEntity challenge =
  M.PublicKeyCredentialCreationOptions
    { M.pkcocRp = M.PublicKeyCredentialRpEntity {M.pkcreId = Nothing, M.pkcreName = "ACME"},
      M.pkcocUser = userEntity,
      M.pkcocChallenge = challenge,
      -- Empty credentialparameters are not supported.
      M.pkcocPubKeyCredParams =
        [ M.PublicKeyCredentialParameters
            { M.pkcpTyp = M.PublicKeyCredentialTypePublicKey,
              M.pkcpAlg = COSEAlgorithmIdentifierES256
            }
        ],
      M.pkcocTimeout = Nothing,
      M.pkcocExcludeCredentials = Nothing,
      M.pkcocAuthenticatorSelection =
        Just
          M.AuthenticatorSelectionCriteria
            { M.ascAuthenticatorAttachment = Nothing,
              M.ascResidentKey = Just M.ResidentKeyRequirementDiscouraged,
              M.ascUserVerification = Just M.UserVerificationRequirementPreferred
            },
      M.pkcocAttestation = Just M.AttestationConveyancePreferenceDirect,
      M.pkcocExtensions = Nothing
    }

main :: IO ()
main = do
  [Text.pack -> origin, Text.pack -> domain, read -> port] <- getArgs
  db <- Database.connect
  Database.initialize db
  sessions <- STM.newTVarIO Map.empty
  Text.putStrLn $ "You can view the web-app at: " <> origin <> "/index.html"
  let rpIdHash = M.RpIdHash $ hash $ Text.encodeUtf8 domain
  Scotty.scotty port $ app (M.Origin origin) rpIdHash db sessions
