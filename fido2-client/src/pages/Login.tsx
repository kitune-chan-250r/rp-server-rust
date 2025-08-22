import { bufferFromBase64Url, bufferToBase64Url } from "../utils";

type AuthenticatorAttestationResponseWithOptionalMembers = AuthenticatorAttestationResponse & {
  getTransports?: () => "" | string[];
  getAuthenticatorData?: () => unknown;
  getPublicKey?: () => unknown;
  getPublicKeyAlgorithm?: () => unknown;
};

type PublicKeyCredentialResponse = {
  response: {
    attestationObject: string;
    clientData: string;
    transports: string[] | undefined;
  };
  rawId: string;
  type: string;
};

type UsernamelessChallengeResponse = {
  challenge: string;
  timeout: number;
  userVerification: UserVerificationRequirement;
};

export const Login = () => {
  /**
   * 1. RPサーバーからチャレンジを取得
   */
  const getChallengeFromRpServer = async () => {
    const response = await fetch("/api/rp/create");
    const challenge = (await response.json()) as PublicKeyCredentialCreationOptionsJSON;
    // (await response.json()) as PublicKeyCredentialCreationOptions;
    console.info(challenge);

    // const challengeOptions = response a;
    return challenge;
  };

  /**
   * 2. 取得したチャレンジ情報を元にブラウザのパスキー認証情報を取得
   */
  const createCredential = async (
    options: PublicKeyCredentialCreationOptionsJSON
    // options: PublicKeyCredentialCreationOptions
  ): Promise<PublicKeyCredential | null> => {
    // const parsedOptions = console.info(parsedOptions);

    try {
      const credential = await navigator.credentials.create({
        publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options),
      });
      if (!credential) {
        console.error("Credential の作成に失敗しました");
        return null;
      } else {
        console.info(credential);
        return credential as PublicKeyCredential;
      }
    } catch (error) {
      console.error(error);
      return null;
    }
  };

  /**
   * 3.
   */
  const fido2CompleteCreateCredential = async (credential: PublicKeyCredential) => {
    // if (
    //   !(credential instanceof PublicKeyCredential) ||
    //   !(credential.response instanceof AuthenticatorAssertionResponse)
    // ) {
    //   // throw new Error(
    //   //   "credential.response is not an instance of AuthenticatorAssertionResponse"
    //   // );
    //   console.error(
    //     "credential.response is not an instance of AuthenticatorAssertionResponse"
    //   );
    //   return;
    // }
    console.info(typeof credential.response);

    console.info("===== credential =====");
    console.info(JSON.stringify(credential, null, 2));
    // const json = credential.response.clientDataJSON;
    // const attestationObjectB64 = credential.response.authenticatorData;
    const response = credential.response as AuthenticatorAttestationResponse;
    const [attestationObjectB64, clientDataJSON_B64] = await Promise.all([
      bufferToBase64Url(response.attestationObject),
      bufferToBase64Url(response.clientDataJSON),
    ]);

    const transports = (
      (
        response as unknown as AuthenticatorAttestationResponseWithOptionalMembers
      ).getTransports?.() || []
    ).filter((transport) => ["ble", "hybrid", "internal", "nfc", "usb"].includes(transport));

    return {
      response: {
        attestationObject: attestationObjectB64,
        clientData: clientDataJSON_B64,
        transports: transports.length ? transports : undefined,
      },
      rawId: bufferToBase64Url(credential.rawId),
      type: credential.type,
    } as PublicKeyCredentialResponse;
  };

  /**
   * 4. RPサーバーからチャレンジを取得
   */
  const registPublicKeyCredential = async (
    credentialResponse: PublicKeyCredentialResponse,
    jsonOptions: PublicKeyCredentialCreationOptionsJSON
  ) => {
    console.info(credentialResponse);
    const response = await fetch("/api/rp/verify", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Challenge": jsonOptions.challenge,
        "UserId": jsonOptions.user.id,
      },
      body: JSON.stringify(credentialResponse),
    });

    // const challengeOptions = response a;
    return await response.json();
  };

  const startRegistFidoAuth = async () => {
    // 1. チャレンジ情報取得
    const jsonOptions = await getChallengeFromRpServer();
    // 2. 取得したチャレンジ情報を元にブラウザのパスキー認証情報を取得
    const credential = await createCredential(jsonOptions);
    if (!credential) {
      console.error("パスキー認証情報の取得に失敗しました");
      return;
    }
    // 3. 取得したパスキー認証情報を元に、チャレンジ情報の検証を行う
    const response = await fido2CompleteCreateCredential(credential);
    // 4. responseをバックエンドの/rp/verifyにPOSTする
    const result = await registPublicKeyCredential(response, jsonOptions);
    console.info("認証結果", result);
  };

  /**
   * FIDO2による認証を開始する
   *
   * 参考にするフローの開始はauthenticateWithFido2()からスタート
   */
  const startAuthenticateWithFido2 = async () => {
    // 1. バックエンドにリクエストを送信し認証チャレンジを取得する
    const auth_challenge = await fetchUsernamelessChallenge();
    // 2. navigator.credentials.get()で署名済みの認証情報を取得する
    const credential = await getFido2Credential({ ...auth_challenge });

    console.debug("Credential obtained:", credential);

    if (!credential) {
      console.error("credential is null");
      return;
    } else if (!(credential instanceof PublicKeyCredential)) {
      console.error("credential is not an instance of PublicKeyCredential");
      return;
    }

    // 3. 取得した認証情報をパースして、必要な情報を抽出する
    const fido2Credential = await parseAuthenticatorAssertionResponse(
      credential.rawId,
      credential.response as AuthenticatorAssertionResponse
    );

    console.debug("fido2Credential: ", fido2Credential);

    verifyChallenge(fido2Credential);
  };

  /**
   * 1. バックエンドにリクエストを送信し
   * 認証チャレンジを作成して受け取る
   */
  const fetchUsernamelessChallenge = async () => {
    const res = await fetch("/api/rp/usernameless/challenge", {
      method: "POST",
    });
    const auth_challenge = (await res.json()) as UsernamelessChallengeResponse;
    return auth_challenge;
  };

  // fido2getCredential
  /**
   * 2. navigator.credentials.get()で認証情報を取得する
   */
  const getFido2Credential = async ({
    challenge,
    timeout,
    userVerification,
  }: {
    challenge: string;
    timeout: number;
    userVerification: UserVerificationRequirement;
  }) => {
    // const rp_name = "manji_rp";
    console.debug("base64challenge", bufferFromBase64Url(challenge));

    const publicKey: CredentialRequestOptions["publicKey"] = {
      challenge: bufferFromBase64Url(challenge),
      timeout,
      userVerification,
      // rpId: relyingPartyId, // 一旦なしでやってみる
      // extensions, // 一旦なしでやってみる
    };
    console.debug("Assembled public key options:", publicKey);
    const credential = await navigator.credentials.get({
      publicKey,
    });

    return credential;
  };

  /**
   * 3. 取得した認証情報をパースして、必要な情報を抽出する
   */
  const parseAuthenticatorAssertionResponse = async (
    rawId: ArrayBuffer,
    response: AuthenticatorAssertionResponse
  ) => {
    const [credentialIdB64, authenticatorDataB64, clientDataJSON_B64, signatureB64, userHandleB64] =
      await Promise.all([
        bufferToBase64Url(rawId),
        bufferToBase64Url(response.authenticatorData),
        bufferToBase64Url(response.clientDataJSON),
        bufferToBase64Url(response.signature),
        response.userHandle && response.userHandle.byteLength > 0
          ? bufferToBase64Url(response.userHandle)
          : null,
      ]);
    return {
      credentialIdB64,
      authenticatorDataB64,
      clientDataJSON_B64,
      signatureB64,
      userHandleB64,
    };
  };

  const verifyChallenge = async ({
    credentialIdB64,
    authenticatorDataB64,
    clientDataJSON_B64,
    signatureB64,
    userHandleB64,
  }: {
    credentialIdB64: string;
    authenticatorDataB64: string;
    clientDataJSON_B64: string;
    signatureB64: string;
    userHandleB64: string | null;
  }) => {
    const res = await fetch("/api/rp/usernameless/verify", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        credentialIdB64,
        authenticatorDataB64,
        clientDataJSON_B64,
        signatureB64,
        userHandleB64,
      }),
    });
    const signinCount = await res.json();

    console.info("verifyChallenge result", signinCount);
  };

  return (
    <div>
      <button onClick={startRegistFidoAuth}>registCredential</button>
      <br />
      <button onClick={startAuthenticateWithFido2}>usernameless auth</button>
    </div>
  );
};
