[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](https://opensource.org/licenses/Apache-2.0)

# BPASS-KOTLIN-SDK
## Abstract
`DID Document`, `credential`, `credential info`, `presentation`을 발급하고 검증하기 위한 SDK입니다.

`holder`, `issuer`, `verifier`, `DID Provider`에 대해 어떤 작업들을 수행하는지 간략하게 소개합니다.

### Owner
`holder`는 개인의 정보를 가지고 있으며, `issuer`로부터 발급된 `credential`을 저장하고 있습니다.
또한 `verifer`에 요청에 따라 `presentation`을 생성하여 `verifer`에 전달 합니다.
 
`holder`는 다음과 같은 역할을 수행 합니다.
1. [키 생성](#key) 
   - 개인키 : `presentation` 서명 생성에 사용 합니다.
   - 공개키 : 및 `DID Document`에 개시 되며, `presentation` 검증에 사용 합니다.
1. 개인 정보에 대한 신원 인증
1. [`DID Document` 생성](#did-document)  
1. [`Credential request` 생성](#Create-credential-request)
   - `issuer`에게 전송하여 증명서(`credential`)를 받을습니다.
1. [`presentation` 생성](#presentation)
   - 개인키를 사용하여 `presentation`을 생성을 생성 합니다.
   - `verifier`에서 `presentation request`가 왔을 경우 `presentation`을 생성하여 `verifier`에 전달 합니다.

### Issuer
`issuer`는  개인의 신원을 인증하고 증명서(`credential`)를 발급해 줍니다.

`issuer`는 다음과 같은 역할을 수행 합니다. 
1. DID 생성(issuer DID 생성)  
1. `credential` 생성
   - `holder`에서 받은 요청(`credential request`)을 사용하여 `credential`을 생성합니다.
1. `credential info` 생성
   - `credential`에 대한 검증에 사용됩니다.

### Verifier
`verifier`는 `holder`에게 presentation을 요청 하여 presentation을 받아 신원을 검증합니다. 

`verifier`는 다음과 같은 역할을 수행 합니다.
1. DID 생성(Verifier DID 생성)  
1. Presentation request 생성  
    - `presentation` 생성할 때 presentation request를 `holder`에게 전달 합니다.
    - `verifier`가 `holder`일 경우 `생략 될 수 있습니다. 
1. Presentation 검증
    - `holder`에게 받은 `presentation`을 검증 합니다.

## Key

#### 키생성
```kotlin
val keyPair = Keys.createSecp256k1KeyPair()
val ecKeyPair = ECKeyPair.create(keyPair)
val walletFile: WalletFile = Wallet.createStandard("PASSWORD", ecKeyPair)

val dir = WalletUtils.defaultKeyDirectory
val fileName = WalletUtils.generateWalletFile(File(dir), walletFile)
```

#### 키 변환
##### WalletFile to ECKeypair
```kotlin
val defaultDir = WalletUtils.defaultKeyDirectory
val directory = File(defaultDir)
val fileName = WalletUtils.generateFullNewWalletFile("PASSWORD", File(defaultDir))

// 키 파일 가져오기
val walletFile: WalletFile = WalletUtils.loadWalletFile(File(directory, fileName))

val walletCredential: Credentials = WalletUtils.loadCredentials("PASSWORD", walletFile)
val ecKeyPair: ECKeyPair = walletCredential.getEcKeyPair()
```

##### BigInt to PrivateKey and PublicKey
```kotlin
val defaultDir = WalletUtils.defaultKeyDirectory
val directory = File(defaultDir)
val fileName = WalletUtils.generateFullNewWalletFile("PASSWORD", File(defaultDir))

// 키 파일 가져오기
val walletFile: WalletFile = WalletUtils.loadWalletFile(File(directory, fileName))

val walletCredential: Credentials = WalletUtils.loadCredentials("PASSWORD", walletFile)
val ecKeyPair: ECKeyPair = walletCredential.getEcKeyPair()

val ecPrivateKey: PrivateKey = ECKeyConverter.bigIntegerToPrivateKey(ecKeyPair.getPrivateKey())
val ecPublicKey: PublicKey = ECKeyConverter.bigIntegerToPublicKey(ecKeyPair.getPublicKey())
```

## DID Document
DID의 사용자 또는 DID의 대리인에 대한 인증을 증명하는데 사용하는 암호화 공개키를 포함한 메타 데이터
 
`holder` 에서 DID 생성 요청문(Create DID Document Request)을 생성하여 `DID Provider`에 전송 하면 DID document를 받을 수 있습니다.

#### DID Document Response
DID Document 생성, 수정, 조회시 `DID Provider`에서 `holder` 에 보내온 Response
```kotlin
val convert = AttributeConverter(DidDocument::class.java)
val didDocument = convert.convertToEntityAttribute(response)
```

#### Create DID Document Request
DID Document를 Balkari blockchain에 등록 하기 위한 JSON 형식의 요청
    - `holder` 에서 `DID Provider`에 전송
```kotlin
// 키생성
val dir = WalletUtils.defaultKeyDirectory
val keyPair = Keys.createSecp256k1KeyPair()
val ecKeyPair = ECKeyPair.create(keyPair)
val walletFile: WalletFile = Wallet.createStandard(SampleKeys.PASSWORD, ecKeyPair)

// DID 생성
val did = Did.createDid(walletFile)

// CreateDidDocumentRequest 생성
val createDidDocumentRequest = CreateDidDocumentRequest.createRequest(ecKeyPair, did.getPublicKeyId(), null)

// CreateDidDocumentRequest json
val convert = AttributeConverter(CreateDidDocumentRequest::class.java)
val json = convert.convertToJson(createDidDocumentRequest)
```
#### Update DID Document Request
Balkari blockchain에 등록된 DID Document를 수정하기 위한 JSON 형식의 요청

- DID Document 수정
```kotlin
val keyPair = Keys.createSecp256k1KeyPair()
val ecKeyPair = ECKeyPair.create(keyPair)
val walletFile: WalletFile = Wallet.createStandard(SampleKeys.PASSWORD, ecKeyPair)

val didDocument = DidDocument.createDidDocument("PASSWORD", walletFile, null)
val did = Did.createDid(walletFile)

val updateDidDocumentRequest = UpdateDidDocumentRequest (
    id = didDocument.id!!,
    publicKeyAttribute = null,
    serviceAttribute = null
)

// public key 추가
updateDidDocumentRequest.addAddPublicKeySet(ecKeyPair, did.getPublicKeyId())

// 기존 public key 폐기   
val publicKeyAttribute = didDocument.publicKeyAttributeSet!!.elementAt(0)
updateDidDocumentRequest.addRevokePublicKeySet(publicKeyAttribute.id!!, PublicKeyRevokeReason.SUPERSEDED)

val serviceId = DidUtils.generateServiceID(didDocument.id!!)
val serviceEndpoint = "http://bpass.balkari.com/validation"
val type = ServiceType.VERIFIABLE_CREDENTIAL_SERVICE

// service 추가
updateDidDocumentRequest.addAddServices(serviceId, type, serviceEndpoint)
```
#### Credential Request
`credential`을 생성하기 위한 요청
    - JWT 형식
    - `holder`에서 `issuer`에 전송
    - `holder`의 서명
 
```kotlin
val keyPair = Keys.createSecp256k1KeyPair()
val ecKeyPair = ECKeyPair.create(keyPair)
val walletFile: WalletFile = Wallet.createStandard("PASSWORD", ecKeyPair)
val didDocument = DidDocument.createDidDocument("PASSWORD", walletFile, null)
val did = Did.createDid(walletFile)

// credentialSubject claim 생성
val credentialSubject: MutableMap<String, Any> = mutableMapOf()
credentialSubject["id"] = didDocument.id!!
credentialSubject["name"] = "Hong Gil-dong"
credentialSubject["birth"] = "20000101"
credentialSubject["account"] = "123412341234"

// Credential Request 생성
val claim = Claim(
    ClaimHeader (
        keyId = did.getPublicKeyId(),
        algorithm = AlgorithmType.KEY_ALG_SECP256K1.algorithmType,
        type = "JWT"
    ),
    ClaimPayload (
        id = did.id,
        credentialSubject = credentialSubject
    )
)

// Credential Request 서명 생성
claim.sign(ecKeyPair)

// Credential Request JWT 생성
val claimJWT = claim.serialize()
```

#### Credential
`holder`의 개인 증명을 `issuer`의 서명이 포함된 증명서
    - JWT 형식
    - `issuer`에서 `holder`에 전송
    - `issuer`의 서명
    
```kotlin

val claimJWT = "eyJraWQiOiJkaWQ6YmFsa2FyaTo3...cZqPuOGBU3rDCvFDLNvaVg"
val claimJwt = Claim.of(claimJWT!!)
if (claimJwt.verify(didDocument.getPublicKey(did.getPublicKeyId()))) {
    println("credential Request verify success.")
}
else {
    println("credential Request verify failed.")
    exitProcess(1)
}

// claim에서 credentialSubject 가져 오기 
val credentialCredentialSubject: MutableMap<String, Any> = (claimJwt.payload as ClaimPayload).credentialSubject!!


// credential 생
val credential = Credential(
    CredentialHeader (
        keyId = issuerDid.getPublicKeyId(),
        algorithm = AlgorithmType.KEY_ALG_SECP256K1.algorithmType,
        type = "JWT"
    ),
    CredentialPayload (
        id = issuerDid.id,
        verifiableCredentialSubject = VerifiableCredentialSubject (
            types = types,
            credentialSubject = credentialCredentialSubject
        )
    )
)

// credential sign
credential.sign(issuerECKeyPair)

// Credential JWT 새성
val credentialJWT = credential.serialize()
```

#### Presentation
여러 `issuer`의 서명이 포함된 증명서 모음을 `holder`가 서명하여 `holder`의 개인 증명을 나타내는 JWT 형식의 토큰 
- JWT 형식
- `holder`에서 `verifier`에 전송
- `holder`의 서명

```kotlin


val credentialJWT1 = "eyJzdWIiOiJkaWQ6YmFsa2...3XY2o5tRr5ZcYRVbfG2yafHml7w"
val credentialJWT2 = "eyJraWQiOiJkaWQ6YmFsa2...gpnZlfwhxB5cNxwV3lKThWnfcJA"
val verifiableCredential: MutableList<String> = mutableListOf()
verifiableCredential.add(credentialJWT1!!)
verifiableCredential.add(credentialJWT2!!)

val presentationTypes: MutableList<String> = mutableListOf()
presentationTypes.add(PresentationType.BALAKRI_PRESENTATION.text)
presentationTypes.add(PresentationType.VERIFIABLE_PRESENTATION.text)

val presentation = Presentation(
    PresentationHeader (
        keyId = issuerDid.getPublicKeyId(),
        algorithm = AlgorithmType.KEY_ALG_SECP256K1.algorithmType,
        type = "JWT"
    ),
    PresentationPayload (
        id = issuerDid.id,
        verifiablePresentation = VerifiablePresentation (
            types = presentationTypes,
            verifiableCredential = verifiableCredential
        )
    )
)
presentation.sign(ecKeyPair)
val presentationJWT = presentation.serialize()
```